package securenet_test

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/shouni/netarmor/securenet"
)

// fuzzResolver is a fixed resolver that keeps fuzzing off real DNS.
// It returns a public IP for the known host only and fails every other lookup.
type fuzzResolver struct{}

func (fuzzResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == "public.test" {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	return nil, &url.Error{Op: "lookup", URL: host, Err: context.DeadlineExceeded}
}

// FuzzValidateURL checks that the URL parsing path never panics and that it holds the
// invariant "a success always has an allowed scheme and a non-empty host".
func FuzzValidateURL(f *testing.F) {
	seeds := []string{
		"https://public.test/api",
		"http://public.test",
		"gs://bucket/object",
		"s3://bucket/key",
		"ftp://example.com/file",
		"http://127.0.0.1/admin",
		"http://[::1]:8080/",
		"http://[::ffff:127.0.0.1]/",
		"http://169.254.169.254/latest/meta-data/",
		"https://",
		"http://",
		"://invalid",
		"example.com",
		"",
		"https://user:pass@public.test:8443/path?q=1#frag",
		"HTTPS://PUBLIC.TEST/",
		"gs://",
		"http://public.test:99999999/",
		"https://public.test/%zz",
		"http://\x00.test/",
		strings.Repeat("a", 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	ctx := context.Background()
	opt := securenet.WithResolver(fuzzResolver{})

	f.Fuzz(func(t *testing.T, raw string) {
		err := securenet.ValidateURL(ctx, raw, opt)
		if err != nil {
			return
		}

		// On success the input must parse and carry an allowed scheme.
		u, parseErr := url.ParseRequestURI(raw)
		if parseErr != nil {
			t.Fatalf("ValidateURL succeeded but the input does not parse: %q", raw)
		}

		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case securenet.SchemeHTTP, securenet.SchemeHTTPS:
			if u.Hostname() == "" {
				t.Fatalf("succeeded with an empty host: %q", raw)
			}
		default:
			t.Fatalf("succeeded with disallowed scheme %q: %q", scheme, raw)
		}
	})
}

// FuzzIsSecureServiceURL checks that every input it returns true for parses
// and has an http/https scheme.
func FuzzIsSecureServiceURL(f *testing.F) {
	seeds := []string{
		"https://example.com",
		"http://localhost:8080",
		"http://host.docker.internal:5000",
		"http://[::1]/",
		"http://example.com",
		"ftp://example.com",
		"https:",
		"https://",
		"",
		"example.com",
		"HTTP://LOCALHOST",
		"https://[::ffff:127.0.0.1]/",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if !securenet.IsSecureServiceURL(raw) {
			return
		}

		u, err := url.ParseRequestURI(raw)
		if err != nil {
			t.Fatalf("returned true but the input does not parse: %q", raw)
		}
		if u.Hostname() == "" {
			t.Fatalf("returned true but the host is empty: %q", raw)
		}

		scheme := strings.ToLower(u.Scheme)
		if scheme != securenet.SchemeHTTP && scheme != securenet.SchemeHTTPS {
			t.Fatalf("returned true but the scheme is %q: %q", scheme, raw)
		}
		if scheme == securenet.SchemeHTTP && !securenet.IsSecureServiceURL("https://"+u.Host) {
			t.Fatalf("allowed http for a host that is not a local development host: %q", raw)
		}
	})
}

// FuzzZonedLiteral checks that adding a zone never loosens the check: if a zoned
// IPv6 literal passes, the same address without the zone must pass as well.
func FuzzZonedLiteral(f *testing.F) {
	seeds := []string{
		"64:ff9b::a9fe:a9fe",
		"2002:a9fe:a9fe::1",
		"2001:db8::1",
		"::ffff:169.254.169.254",
		"fe80::1",
		"::1",
		"2606:4700:4700::1111",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	ctx := context.Background()
	opt := securenet.WithResolver(fuzzResolver{})

	f.Fuzz(func(t *testing.T, raw string) {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return
		}

		zoned := "http://[" + addr.String() + "%25eth0]/"
		if securenet.ValidateURL(ctx, zoned, opt) != nil {
			return
		}
		plain := "http://[" + addr.String() + "]/"
		if err := securenet.ValidateURL(ctx, plain, opt); err != nil {
			t.Fatalf("the zoned form passed but the unzoned form was rejected: %q: %v", plain, err)
		}
	})
}
