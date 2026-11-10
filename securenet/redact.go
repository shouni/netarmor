package securenet

import (
	"net/url"
	"strings"
)

// redactedQuery replaces a redacted query. It keeps only the fact that a query was present.
const redactedQuery = "REDACTED"

// redactedUserinfo replaces the userinfo of a URL that cannot be parsed.
// It matches the placeholder url.URL.Redacted uses for passwords.
const redactedUserinfo = "xxxxx"

// redactURL returns the URL string to put in an error.
//
// Errors end up in logs verbatim. A query can carry a signed URL's signature or a
// `?key=` API key, while url.URL.Redacted hides only the userinfo password. So the
// query and fragment values are dropped, keeping only the fact they were present.
// Scheme, host and path are enough to trace which connection was refused.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	if c.RawQuery != "" || c.ForceQuery {
		c.RawQuery = redactedQuery
		c.ForceQuery = false
	}
	c.Fragment, c.RawFragment = "", ""
	return c.Redacted()
}

// redactURLString is the string version of redactURL.
//
// Its main use is input that cannot be parsed, which ends up in a URLError. Even then,
// everything from `?` / `#` on may hold secrets and is cut off, and if the authority
// after `://` contains `@`, the whole userinfo is redacted (there is nothing to tell
// the password apart by).
func redactURLString(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return redactURL(u)
	}

	s := raw
	suffix := ""
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
		suffix = "?" + redactedQuery
	}
	if i := strings.Index(s, "://"); i >= 0 {
		authStart := i + len("://")
		authEnd := len(s)
		if j := strings.IndexByte(s[authStart:], '/'); j >= 0 {
			authEnd = authStart + j
		}
		if at := strings.LastIndexByte(s[authStart:authEnd], '@'); at >= 0 {
			s = s[:authStart] + redactedUserinfo + s[authStart+at:]
		}
	}
	return s + suffix
}

// redactParseError returns a copy of a url package parse error with the input redacted.
//
// A failure from url.Parse / url.ParseRequestURI is a *url.Error that holds the raw
// input. Redacting URLError's URL alone would still leave it in the original error's
// text. Because a copy is substituted, extracting the *url.Error with errors.As
// works as before.
func redactParseError(err error) error {
	ue, ok := err.(*url.Error)
	if !ok || ue == nil {
		return err
	}
	c := *ue
	c.URL = redactURLString(ue.URL)
	return &c
}
