package securenet

import (
	"errors"
	"fmt"
	"net/netip"
)

// Sentinel errors. Callers can tell failure reasons apart with errors.Is.
//
// Error messages follow Go convention: English, lowercase, no trailing punctuation.
// To show a localized message, classify with errors.Is / errors.As and build the
// message on the caller's side.
var (
	// ErrRestrictedIP reports that name resolution returned an address in a restricted network.
	// To get the offending IP address, extract a *BlockedIPError with errors.As.
	ErrRestrictedIP = errors.New("securenet: restricted network")

	// ErrDisallowedScheme reports that the URL's scheme is not allowed.
	ErrDisallowedScheme = errors.New("securenet: disallowed scheme")

	// ErrEmptyHost reports that the URL has no hostname.
	ErrEmptyHost = errors.New("securenet: empty host")

	// ErrNoAddresses reports that name resolution succeeded but returned no addresses.
	ErrNoAddresses = errors.New("securenet: hostname resolved to no addresses")

	// ErrInvalidURL reports that the URL failed to parse.
	ErrInvalidURL = errors.New("securenet: invalid URL")

	// ErrTooManyRedirects reports that the redirect limit was reached.
	ErrTooManyRedirects = errors.New("securenet: too many redirects")

	// ErrRedirectDowngrade reports that a redirect from https to http was refused.
	ErrRedirectDowngrade = errors.New("securenet: redirect downgrade")
)

// BlockedIPError reports that a connection to a restricted network was blocked.
// errors.Is(err, ErrRestrictedIP) is true for it.
type BlockedIPError struct {
	// Host is the hostname that was checked.
	Host string
	// Addr is the IP address judged to be restricted.
	Addr netip.Addr
}

func (e *BlockedIPError) Error() string {
	return fmt.Sprintf("securenet: restricted network: host %q resolved to %s", e.Host, e.Addr)
}

// Unwrap returns ErrRestrictedIP so that errors.Is can classify the error.
func (e *BlockedIPError) Unwrap() error { return ErrRestrictedIP }

// SchemeError reports that a disallowed scheme was given.
// errors.Is(err, ErrDisallowedScheme) is true for it.
type SchemeError struct {
	// Scheme is the rejected scheme, lowercased.
	Scheme string
}

func (e *SchemeError) Error() string {
	return fmt.Sprintf("securenet: disallowed scheme %q", e.Scheme)
}

// Unwrap returns ErrDisallowedScheme so that errors.Is can classify the error.
func (e *SchemeError) Unwrap() error { return ErrDisallowedScheme }

// ResolveError reports that resolving the hostname failed.
// The underlying DNS error is available through Unwrap.
type ResolveError struct {
	// Host is the hostname that failed to resolve.
	Host string
	// Err is the original error returned by the resolver.
	Err error
}

func (e *ResolveError) Error() string {
	return fmt.Sprintf("securenet: lookup %q: %v", e.Host, e.Err)
}

// Unwrap returns the original error returned by the resolver.
func (e *ResolveError) Unwrap() error { return e.Err }

// URLError reports that the URL failed to parse.
// errors.Is(err, ErrInvalidURL) is true for it.
type URLError struct {
	// URL is the input that failed to parse. Errors end up in logs verbatim, so it
	// holds a form with the query and fragment values and the userinfo redacted.
	URL string
	// Err is the original error returned by the url package, and may be nil.
	// The URL inside a *url.Error is redacted the same way.
	Err error
}

func (e *URLError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("securenet: invalid URL %q", e.URL)
	}
	return fmt.Sprintf("securenet: invalid URL %q: %v", e.URL, e.Err)
}

// Unwrap returns both ErrInvalidURL and the original parse error, so errors.Is
// can classify the error and the cause can still be retrieved.
func (e *URLError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrInvalidURL}
	}
	return []error{ErrInvalidURL, e.Err}
}

// TooManyRedirectsError reports that redirect following stopped at the limit.
// errors.Is(err, ErrTooManyRedirects) is true for it.
//
// The error is returned from the *http.Client's CheckRedirect, so it reaches the
// caller wrapped in a *url.Error. errors.Is / errors.As see through that wrapper.
type TooManyRedirectsError struct {
	// Max is the configured redirect limit.
	Max int
}

func (e *TooManyRedirectsError) Error() string {
	return fmt.Sprintf("securenet: stopped after %d redirects", e.Max)
}

// Unwrap returns ErrTooManyRedirects so that errors.Is can classify the error.
func (e *TooManyRedirectsError) Unwrap() error { return ErrTooManyRedirects }

// RedirectDowngradeError reports that following a redirect from https to http was refused.
// errors.Is(err, ErrRedirectDowngrade) is true for it.
type RedirectDowngradeError struct {
	// URL is the redirect target. It holds a form with the password and the query
	// and fragment values redacted, since those can carry a signed URL's signature
	// or an API key.
	URL string
}

func (e *RedirectDowngradeError) Error() string {
	return fmt.Sprintf("securenet: refusing redirect downgrade from https to http (%s)", e.URL)
}

// Unwrap returns ErrRedirectDowngrade so that errors.Is can classify the error.
func (e *RedirectDowngradeError) Unwrap() error { return ErrRedirectDowngrade }
