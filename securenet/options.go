package securenet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"
)

// Resolver abstracts name resolution. *net.Resolver satisfies it as is, so production
// can use net.DefaultResolver and tests can inject a fake.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// defaultBlockedPrefixes lists the additional networks to block that the standard
// library's predicates (IsPrivate, IsLoopback and so on) do not cover.
//
//   - 0.0.0.0/8         : "this network" (RFC 1122)
//   - 100.64.0.0/10     : Carrier-grade NAT (RFC 6598)
//   - 192.0.0.0/24      : IETF protocol assignments (RFC 6890)
//   - 192.0.2.0/24      : TEST-NET-1 (RFC 5737)
//   - 192.88.99.0/24    : 6to4 relay anycast (deprecated, RFC 7526)
//   - 198.18.0.0/15     : benchmarking (RFC 2544)
//   - 198.51.100.0/24   : TEST-NET-2 (RFC 5737)
//   - 203.0.113.0/24    : TEST-NET-3 (RFC 5737)
//   - 240.0.0.0/4       : reserved (RFC 1112)
//   - 64:ff9b::/96      : NAT64 well-known prefix (RFC 6052)
//   - 64:ff9b:1::/48    : local-use IPv4/IPv6 translation (RFC 8215)
//   - 100::/64          : Discard-Only (RFC 6666)
//   - 2001::/32         : Teredo (RFC 4380)
//   - 2001:db8::/32     : documentation (RFC 3849)
//   - 2002::/16         : 6to4 (RFC 3056)
//   - 3fff::/20         : documentation, expanded (RFC 9637)
//   - 5f00::/16         : SRv6 SID (RFC 9602)
//   - fec0::/10         : site-local (deprecated, RFC 3879)
//
// The NAT64 / 6to4 / Teredo transition ranges can embed an IPv4 address, so they can
// become a route to an embedded internal IPv4 address (for example, 64:ff9b::a9fe:a9fe
// is the metadata endpoint). Rather than checking each embedded address, the whole
// range is blocked, failing closed. If a NAT64 environment legitimately needs one,
// allow it explicitly with WithAllowedCIDRs (note that the embedded IPv4 address is
// then not checked).
var defaultBlockedPrefixes = mustParsePrefixes(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/32",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
	"5f00::/16",
	"fec0::/10",
)

// policy decides whether a connection to a given IP address is allowed.
type policy struct {
	allowed        []netip.Prefix
	blocked        []netip.Prefix
	allowLoopback  bool
	allowPrivate   bool
	allowLinkLocal bool
}

// isRestricted reports whether connecting to addr is forbidden.
//
// The evaluation order is allowlist, then standard-library predicates, then blocklist.
// The allowlist comes first, so an address explicitly allowed with WithAllowedCIDRs
// is allowed ahead of every other rule.
func (p *policy) isRestricted(addr netip.Addr) bool {
	// Normalise IPv4-mapped IPv6 (::ffff:127.0.0.1) to IPv4 before checking.
	// Without this, the mapped form could slip past the private-IP checks.
	//
	// Drop the zone as well. netip.Prefix.Contains always returns false for a zoned
	// address, so keeping it would let a bare zone, as in
	// [64:ff9b::a9fe:a9fe%25eth0], slip past the blocked-range check.
	a := addr.Unmap().WithZone("")

	if !a.IsValid() {
		return true
	}

	for _, pre := range p.allowed {
		if pre.Contains(a) {
			return false
		}
	}

	switch {
	case a.IsLoopback():
		return !p.allowLoopback
	case a.IsPrivate():
		return !p.allowPrivate
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return !p.allowLinkLocal
	// IsMulticast covers all of IPv6 ff00::/8, so interface-local multicast
	// (ff01::/16) needs no separate check.
	case a.IsUnspecified(), a.IsMulticast():
		return true
	}

	for _, pre := range p.blocked {
		if pre.Contains(a) {
			return true
		}
	}

	return false
}

// options is the configuration shared by securenet's constructors.
type options struct {
	policy         policy
	resolver       Resolver
	proxy          func(*http.Request) (*url.URL, error)
	baseTransport  *http.Transport
	dialer         *net.Dialer
	maxRedirects   int
	allowDowngrade bool
}

// Option adjusts securenet's behavior.
type Option func(*options)

// defaultOptions returns the safe defaults used when nothing is specified.
func defaultOptions() options {
	return options{
		policy: policy{
			// Clip makes cap == len, so WithBlockedCIDRs' append cannot overwrite
			// the package-wide backing array.
			blocked: slices.Clip(defaultBlockedPrefixes),
		},
		resolver:     net.DefaultResolver,
		proxy:        nil, // the environment proxy is disabled by default
		maxRedirects: 10,
	}
}

func newOptions(opts []Option) *options {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return &o
}

// WithResolver replaces the resolver used for name resolution.
// Use it in tests to avoid depending on real DNS.
func WithResolver(r Resolver) Option {
	return func(o *options) {
		if r != nil {
			o.resolver = r
		}
	}
}

// WithProxy sets the function that selects the HTTP proxy.
//
// Proxies are disabled by default, so that HTTP_PROXY / HTTPS_PROXY cannot be abused
// to route around IP validation. Environments that must go through a corporate proxy
// can enable one explicitly with this option.
//
// With a proxy, the address DialContext receives is the proxy server's. Note two
// consequences:
//
//   - The final destination IP is not validated. The proxy itself must be trusted.
//   - If the proxy sits at a private address, the default policy rejects the
//     connection to it. Allow the proxy's address explicitly with WithAllowedCIDRs.
func WithProxy(fn func(*http.Request) (*url.URL, error)) Option {
	return func(o *options) { o.proxy = fn }
}

// WithProxyFromEnvironment enables HTTP_PROXY / HTTPS_PROXY / NO_PROXY.
// See WithProxy for the trade-offs.
func WithProxyFromEnvironment() Option {
	return WithProxy(http.ProxyFromEnvironment)
}

// WithAllowedCIDRs adds networks to which connections are allowed even when the
// default policy would reject them. The allowlist takes precedence over every other check.
//
// Invalid CIDR notation is ignored. To validate it beforehand, use netip.ParsePrefix.
func WithAllowedCIDRs(cidrs ...string) Option {
	return func(o *options) {
		for _, c := range cidrs {
			if pre, err := netip.ParsePrefix(c); err == nil {
				o.policy.allowed = append(o.policy.allowed, pre.Masked())
			}
		}
	}
}

// WithAllowedPrefixes is the pre-parsed version of WithAllowedCIDRs.
func WithAllowedPrefixes(prefixes ...netip.Prefix) Option {
	return func(o *options) {
		for _, pre := range prefixes {
			o.policy.allowed = append(o.policy.allowed, pre.Masked())
		}
	}
}

// WithBlockedCIDRs adds networks to the default blocklist.
//
// Invalid CIDR notation is ignored. To validate it beforehand, use netip.ParsePrefix.
func WithBlockedCIDRs(cidrs ...string) Option {
	return func(o *options) {
		for _, c := range cidrs {
			if pre, err := netip.ParsePrefix(c); err == nil {
				o.policy.blocked = append(o.policy.blocked, pre.Masked())
			}
		}
	}
}

// WithAllowLoopback allows connections to loopback addresses.
// Use it, for example, when tests target an httptest.NewServer.
// Enabling it in production seriously weakens SSRF protection.
func WithAllowLoopback() Option {
	return func(o *options) { o.policy.allowLoopback = true }
}

// WithAllowPrivate allows connections to RFC 1918 private addresses.
// Enabling it in production seriously weakens SSRF protection.
func WithAllowPrivate() Option {
	return func(o *options) { o.policy.allowPrivate = true }
}

// WithAllowLinkLocal allows connections to link-local addresses.
// It makes cloud metadata endpoints such as 169.254.169.254 reachable, so avoid
// enabling it whenever possible.
func WithAllowLinkLocal() Option {
	return func(o *options) { o.policy.allowLinkLocal = true }
}

// WithBaseTransport sets the *http.Transport to clone from.
// Use it to bring in HTTP/2 settings or connection-pool tuning.
//
// The given Transport is cloned, and securenet then overwrites these fields:
//
//   - Proxy / DialContext: replaced with the validating implementations.
//   - DialTLSContext / DialTLS / Dial: set to nil. With DialTLSContext set, HTTPS
//     never calls DialContext and IP validation is bypassed, so this package
//     disables it. Configure TLS through TLSClientConfig instead.
func WithBaseTransport(t *http.Transport) Option {
	return func(o *options) { o.baseTransport = t }
}

// WithDialer replaces the *net.Dialer used to connect.
// Use it, for example, to use the Dialer's Control hook.
// When set, the timeout passed to the constructor is not applied to the Dialer,
// so set the Dialer's Timeout yourself if needed.
func WithDialer(d *net.Dialer) Option {
	return func(o *options) { o.dialer = d }
}

// WithMaxRedirects sets the maximum number of redirects to follow.
// 0 follows no redirects at all. A negative value is treated as the default (10).
//
// When the limit is reached, the request fails with a *TooManyRedirectsError
// (errors.Is(err, ErrTooManyRedirects) is true).
func WithMaxRedirects(n int) Option {
	return func(o *options) {
		if n >= 0 {
			o.maxRedirects = n
		}
	}
}

// WithAllowRedirectDowngrade allows following redirects from https to http.
//
// By default, a redirect that downgrades is refused with a *RedirectDowngradeError
// (errors.Is(err, ErrRedirectDowngrade) is true).
func WithAllowRedirectDowngrade() Option {
	return func(o *options) { o.allowDowngrade = true }
}

func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		pre, err := netip.ParsePrefix(c)
		if err != nil {
			panic(fmt.Sprintf("securenet: invalid blocked prefix %q: %v", c, err))
		}
		prefixes = append(prefixes, pre.Masked())
	}
	return prefixes
}

// newDialer builds the Dialer used to connect from the options.
func (o *options) newDialer(timeout time.Duration) *net.Dialer {
	if o.dialer != nil {
		return o.dialer
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
}
