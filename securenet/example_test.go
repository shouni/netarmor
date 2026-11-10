package securenet_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"time"

	"github.com/shouni/netarmor/securenet"
)

// exampleResolver is a fixed resolver that keeps the examples deterministic.
// Real code leaves the resolver unset and uses the default net.DefaultResolver.
type exampleResolver map[string][]netip.Addr

func (r exampleResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

var demoResolver = exampleResolver{
	"api.example.com":      {netip.MustParseAddr("93.184.216.34")},
	"internal.example.com": {netip.MustParseAddr("10.0.0.5")},
}

func ExampleValidateURL() {
	ctx := context.Background()

	// A host that resolves to a public IP is allowed
	fmt.Println(securenet.ValidateURL(ctx, "https://api.example.com/v1",
		securenet.WithResolver(demoResolver)))

	// A host that resolves to a private IP is rejected
	fmt.Println(securenet.ValidateURL(ctx, "https://internal.example.com/admin",
		securenet.WithResolver(demoResolver)))

	// Output:
	// <nil>
	// securenet: restricted network: host "internal.example.com" resolved to 10.0.0.5
}

// Validation errors can be classified with errors.Is / errors.As.
func ExampleValidateURL_errorHandling() {
	ctx := context.Background()

	err := securenet.ValidateURL(ctx, "ftp://example.com/file",
		securenet.WithResolver(demoResolver))

	fmt.Println("disallowed scheme:", errors.Is(err, securenet.ErrDisallowedScheme))

	if se, ok := errors.AsType[*securenet.SchemeError](err); ok {
		fmt.Println("scheme:", se.Scheme)
	}

	err = securenet.ValidateURL(ctx, "https://internal.example.com/",
		securenet.WithResolver(demoResolver))

	if blocked, ok := errors.AsType[*securenet.BlockedIPError](err); ok {
		fmt.Printf("blocked: %s -> %s\n", blocked.Host, blocked.Addr)
	}

	// Output:
	// disallowed scheme: true
	// scheme: ftp
	// blocked: internal.example.com -> 10.0.0.5
}

func ExampleNewSafeHTTPClient() {
	client := securenet.NewSafeHTTPClient(10 * time.Second)

	// The cloud metadata endpoint is blocked at the DialContext layer
	_, err := client.Get("http://169.254.169.254/latest/meta-data/")

	fmt.Println("blocked:", errors.Is(err, securenet.ErrRestrictedIP))
	// Output: blocked: true
}

// Tests can explicitly allow connections to a local server.
func ExampleWithAllowLoopback() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithAllowLoopback())

	resp, err := client.Get(server.URL)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	_ = resp.Body.Close()

	fmt.Println("status:", resp.StatusCode)
	// Output: status: 200
}

// To assemble your own *http.Client, take just the Transport.
func ExampleNewSafeTransport() {
	transport := securenet.NewSafeTransport(10 * time.Second)

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		// a cookie jar and redirect policy can be set as you like
	}

	_, err := client.Get("http://10.0.0.1/internal")
	fmt.Println("blocked:", errors.Is(err, securenet.ErrRestrictedIP))
	// Output: blocked: true
}

// When an internal network must be reachable, allow just that range.
func ExampleWithAllowedCIDRs() {
	ctx := context.Background()

	opts := []securenet.Option{
		securenet.WithResolver(demoResolver),
		securenet.WithAllowedCIDRs("10.0.0.0/8"),
	}

	// The allowed range passes
	fmt.Println(securenet.ValidateURL(ctx, "https://internal.example.com/", opts...))

	// Ranges that were not allowed are still rejected
	err := securenet.ValidateURL(ctx, "http://192.168.1.1/", opts...)
	fmt.Println("still blocked:", errors.Is(err, securenet.ErrRestrictedIP))

	// Output:
	// <nil>
	// still blocked: true
}

func ExampleIsSecureServiceURL() {
	// A configuration sanity check that does no name resolution
	fmt.Println(securenet.IsSecureServiceURL("https://api.example.com"))
	fmt.Println(securenet.IsSecureServiceURL("http://localhost:8080"))
	fmt.Println(securenet.IsSecureServiceURL("http://api.example.com"))

	// Output:
	// true
	// true
	// false
}
