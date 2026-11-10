// Package securenet provides SSRF (Server-Side Request Forgery) protection: URL scheme
// validation and HTTP clients hardened against DNS rebinding.
//
// # Two layers of defense
//
// The package provides two validation layers with different purposes. Use both.
//
//  1. Static validation (ValidateURL): a pre-check that rejects a URL before any request
//     is sent. It suits returning an error early, as soon as user input is accepted.
//  2. Connect-time validation (NewSafeHTTPClient / NewSafeTransport): the real defense
//     against TOCTOU attacks such as DNS rebinding. It resolves the name right before
//     the connection is established and dials the validated IP address directly.
//
// Static validation alone cannot stop an attack that swaps the DNS answer after the
// check and before the connection. The authoritative defense is always connect-time
// validation.
//
// # Failing closed
//
// When a hostname resolves to several IP addresses, the whole connection is rejected
// if any one of them is restricted. Connecting only to the "safe" addresses is not
// done, because it can be bypassed whenever an attacker can influence resolution order.
//
// # Proxies
//
// The clients do not use HTTP_PROXY / HTTPS_PROXY by default, so that environment
// variables cannot be used to route around IP validation. To enable a proxy
// explicitly, use WithProxy or WithProxyFromEnvironment.
package securenet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// SchemeHTTP is the plaintext HTTP scheme.
	// IsSecureServiceURL allows it only together with a local development hostname
	// (ValidateURL and connect-time validation allow http to any unrestricted host).
	SchemeHTTP = "http"
	// SchemeHTTPS is the encrypted HTTPS scheme.
	SchemeHTTPS = "https"
)

// localdevHostnames is the set of hostnames commonly used for local development.
var localdevHostnames = map[string]struct{}{
	"localhost":            {},
	"127.0.0.1":            {},
	"::1":                  {},
	"host.docker.internal": {},
}

// IsSecureServiceURL reports whether the given service URL uses a secure scheme or
// matches a local development hostname.
//
// It is a lightweight sanity check for configuration values and does no name
// resolution. It does not answer "is it safe to actually fetch this URL", so use
// ValidateURL to validate URLs supplied from outside.
func IsSecureServiceURL(serviceURL string) bool {
	u, err := url.ParseRequestURI(serviceURL)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return false
	}

	switch u.Scheme { // url.Parse has already lowercased the scheme
	case SchemeHTTPS:
		return true
	case SchemeHTTP:
		return isLocalDevHostname(hostname)
	default:
		return false
	}
}

// ValidateURL statically validates a URL to prevent SSRF attacks.
// It returns nil when the URL is judged safe, and otherwise an error describing why not.
//
// The returned error can be classified with errors.Is / errors.As.
//
//	err := securenet.ValidateURL(ctx, rawURL)
//	switch {
//	case errors.Is(err, securenet.ErrRestrictedIP):
//		// access to a restricted network
//	case errors.Is(err, securenet.ErrDisallowedScheme):
//		// disallowed scheme
//	}
//
// Only the http and https schemes are allowed. Every other scheme is
// ErrDisallowedScheme.
//
// Control the name-resolution timeout through ctx. This function sets no timeout of its own.
func ValidateURL(ctx context.Context, rawURL string, opts ...Option) error {
	return newOptions(opts).validateURL(ctx, rawURL)
}

// NewSafeTransport returns an *http.Transport that validates the IP right before connecting.
//
// Use it to build your own *http.Client (with a cookie jar or instrumentation).
// If you just want a safe client, use NewSafeHTTPClient.
//
// The redirect policy (WithMaxRedirects / WithAllowRedirectDowngrade) is a feature of
// *http.Client.CheckRedirect, so the returned Transport does not include it. With an
// *http.Client of your own, those options are ignored and Go's default behavior applies
// (up to 10 redirects, with no restriction on https-to-http downgrades).
// If you need redirect control, use NewSafeHTTPClient.
func NewSafeTransport(timeout time.Duration, opts ...Option) *http.Transport {
	return newOptions(opts).newTransport(timeout)
}

// NewSafeHTTPClient returns a client that prevents DNS rebinding by validating the IP
// right before connecting.
//
// By default the following policy applies:
//   - connections to private, loopback, link-local and similar addresses are refused
//   - proxies from environment variables are disabled
//   - at most 10 redirects are followed, and https-to-http downgrades are refused
//
// Each of these can be adjusted with an Option.
func NewSafeHTTPClient(timeout time.Duration, opts ...Option) *http.Client {
	o := newOptions(opts)
	return &http.Client{
		Transport:     o.newTransport(timeout),
		Timeout:       timeout,
		CheckRedirect: o.checkRedirect,
	}
}

// newTransport builds a validating Transport from the options.
func (o *options) newTransport(timeout time.Duration) *http.Transport {
	transport := o.cloneBaseTransport()
	transport.Proxy = o.proxy
	transport.DialContext = o.dialContext(o.newDialer(timeout))

	// With DialTLSContext set, HTTPS never calls DialContext and IP validation is
	// bypassed entirely (net/http behavior). Disable it to stay on the safe side.
	//
	// Drop the deprecated DialTLS / Dial too. DialTLS is still live in net/http's
	// customDialTLS as the fallback when DialTLSContext is nil, so leaving it would
	// leave a hole. Dial is never reached because DialContext is always set, but it is
	// cleared as well for defense in depth.
	transport.DialTLSContext = nil
	transport.DialTLS = nil //nolint:staticcheck // assigned to disable it so validation cannot be bypassed, not to use it
	transport.Dial = nil    //nolint:staticcheck // same as above

	return transport
}

// cloneBaseTransport picks the Transport to clone from and clones it.
func (o *options) cloneBaseTransport() *http.Transport {
	if o.baseTransport != nil {
		return o.baseTransport.Clone()
	}
	// http.DefaultTransport may have been replaced globally, for example by an
	// instrumentation library. So that the type assertion cannot panic, build from
	// defaults equivalent to the standard ones when it is not an *http.Transport.
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		return dt.Clone()
	}
	return &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// dialContext returns a dial function that resolves the name and validates the IP right before connecting.
func (o *options) dialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// net.Dialer.Timeout applies per DialContext call, so calling it once per
		// resolved address could stretch the total to "number of addresses x timeout".
		// As with the standard net.Dialer, bound the whole dial, name resolution included.
		if dialer.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dialer.Timeout)
			defer cancel()
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("securenet: split host port %q: %w", addr, err)
		}

		// Resolve right before connecting and validate the resolved IPs at once (TOCTOU defense)
		addrs, err := o.resolveAndCheck(ctx, host)
		if err != nil {
			return nil, err
		}

		// Dial the validated IPs directly. Re-dialing by hostname would resolve the
		// name again here, and validation could be bypassed.
		//
		// The deadline is split across the remaining addresses for each attempt (the
		// same split as net.Dialer). Passing the whole deadline as is would let a
		// black-holed first IP use it all up, and a reachable second IP would never
		// be tried.
		var lastErr error
		for i, a := range addrs {
			attemptCtx, cancel := attemptContext(ctx, len(addrs)-i)
			conn, err := dialer.DialContext(attemptCtx, network, net.JoinHostPort(a.String(), port))
			cancel()
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}

// attemptContext returns a context whose deadline is this attempt's share among the
// addrsRemaining addresses left. If ctx has no deadline, it is returned as is.
func attemptContext(ctx context.Context, addrsRemaining int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, partialDeadline(time.Now(), deadline, addrsRemaining))
}

// partialDeadline returns a deadline that divides the remaining time evenly among the
// addresses not yet tried. When a single attempt's share is too short, it borrows from
// the later addresses up to saneMinimum (the same rule as net.Dialer's partialDeadline).
func partialDeadline(now, deadline time.Time, addrsRemaining int) time.Time {
	const saneMinimum = 2 * time.Second
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return now
	}
	timeout := timeRemaining / time.Duration(addrsRemaining)
	if timeout < saneMinimum {
		timeout = min(timeRemaining, saneMinimum)
	}
	return now.Add(timeout)
}

// checkRedirect decides whether a redirect may be followed.
// Its errors can be compared with ErrTooManyRedirects / ErrRedirectDowngrade using errors.Is.
func (o *options) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > o.maxRedirects {
		return &TooManyRedirectsError{Max: o.maxRedirects}
	}
	if !o.allowDowngrade && len(via) > 0 {
		prev := via[len(via)-1]
		if prev.URL.Scheme == SchemeHTTPS && req.URL.Scheme == SchemeHTTP {
			return &RedirectDowngradeError{URL: redactURL(req.URL)}
		}
	}
	return nil
}

// validateURL validates the URL's scheme and hostname.
func (o *options) validateURL(ctx context.Context, rawURL string) error {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return &URLError{URL: redactURLString(rawURL), Err: redactParseError(err)}
	}

	switch parsed.Scheme { // url.Parse has already lowercased the scheme
	case SchemeHTTP, SchemeHTTPS:
		// continue validating
	default:
		return &SchemeError{Scheme: parsed.Scheme}
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return fmt.Errorf("%w: %q", ErrEmptyHost, redactURL(parsed))
	}

	_, err = o.resolveAndCheck(ctx, hostname)
	return err
}

// resolveAndCheck resolves the hostname and checks that every result is allowed by the policy.
// If any one of them is restricted, it fails closed and returns an error.
func (o *options) resolveAndCheck(ctx context.Context, host string) ([]netip.Addr, error) {
	// IP literals are validated directly, without the resolver.
	if a, err := netip.ParseAddr(host); err == nil {
		if o.policy.isRestricted(a) {
			return nil, &BlockedIPError{Host: host, Addr: a}
		}
		return []netip.Addr{a}, nil
	}

	addrs, err := o.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, &ResolveError{Host: host, Err: err}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoAddresses, host)
	}

	for _, a := range addrs {
		if o.policy.isRestricted(a) {
			return nil, &BlockedIPError{Host: host, Addr: a}
		}
	}
	return addrs, nil
}

// isLocalDevHostname reports whether hostname matches a known local development hostname.
func isLocalDevHostname(hostname string) bool {
	_, ok := localdevHostnames[hostname]
	return ok
}
