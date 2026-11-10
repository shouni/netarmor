package securenet_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shouni/netarmor/securenet"
)

// stubRoundTripper reproduces an http.DefaultTransport that is not an *http.Transport.
type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("stub round tripper")
}

// fakeResolver is a test resolver that reproduces name resolution without real DNS,
// so the tests run deterministically even offline.
type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	raw, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	addrs := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	return addrs, nil
}

// errResolver is a resolver that always fails.
type errResolver struct{ err error }

func (e errResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, e.err
}

// emptyResolver is a resolver that succeeds but returns no addresses.
type emptyResolver struct{}

func (emptyResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, nil
}

var testResolver = fakeResolver{
	"localhost":       {"127.0.0.1"},
	"example.com":     {"93.184.216.34"},
	"public.test":     {"93.184.216.34", "2606:2800:220:1::1"},
	"internal.test":   {"10.0.0.1"},
	"mixed.test":      {"93.184.216.34", "192.168.1.1"}, // one restricted address rejects the whole host
	"mapped.test":     {"::ffff:127.0.0.1"},             // attempted bypass via IPv4-mapped IPv6
	"metadata.test":   {"169.254.169.254"},
	"cgnat.test":      {"100.64.0.1"},
	"benchmark.test":  {"198.18.0.1"},
	"docexample.test": {"2001:db8::1"},
}

// ----------------------------------------------------------------------
// TestIsSecureServiceURL: HTTPS / local-development checks (no name resolution)
// ----------------------------------------------------------------------

func TestIsSecureServiceURL(t *testing.T) {
	tests := []struct {
		name     string
		inputURL string
		want     bool
	}{
		{"HTTPS_ValidURL", "https://example.com/api", true},
		{"HTTPS_WithPort", "https://example.com:8443/secure", true},
		{"HTTP_Localhost", "http://localhost:8080/api", true},
		{"HTTP_127.0.0.1", "http://127.0.0.1:3000", true},
		{"HTTP_IPv6_Loopback", "http://[::1]:8080/test", true},
		{"HTTP_DockerInternal", "http://host.docker.internal:5000", true},
		{"HTTP_ExternalHost_Insecure", "http://example.com/api", false},
		{"HTTP_MixedCase_Localhost", "http://LocalHost:8080", true},
		{"FTP_Scheme_Invalid", "ftp://example.com/file", false},
		{"InvalidURL_ParseError", "://invalid-url", false},
		{"EmptyURL", "", false},
		{"NoScheme", "example.com", false},
		{"HTTPS_EmptyHost", "https:", false},
		{"HTTPS_EmptyHostWithSlashes", "https://", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := securenet.IsSecureServiceURL(tt.inputURL); got != tt.want {
				t.Errorf("URL %q: want %v, got %v", tt.inputURL, tt.want, got)
			}
		})
	}
}

// ----------------------------------------------------------------------
// TestValidateURL: URL validation for SSRF protection
// ----------------------------------------------------------------------

func TestValidateURL(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		inputURL string
		wantErr  error // nil means success is expected
	}{
		{"HTTPS_PublicDomain", "https://example.com/api", nil},
		{"HTTP_PublicDomain", "http://example.com/data", nil},
		{"HTTPS_DualStack_Public", "https://public.test/api", nil},

		{"HTTP_Localhost_Restricted", "http://localhost/admin", securenet.ErrRestrictedIP},
		{"HTTP_127.0.0.1_Restricted", "http://127.0.0.1:8080/secret", securenet.ErrRestrictedIP},
		{"HTTP_PrivateIP_10.0.0.1", "http://10.0.0.1/internal", securenet.ErrRestrictedIP},
		{"HTTP_PrivateIP_192.168.1.1", "http://192.168.1.1/router", securenet.ErrRestrictedIP},
		{"HTTP_UnspecifiedIP", "http://0.0.0.0/admin", securenet.ErrRestrictedIP},
		{"HTTP_CGNAT", "http://100.64.0.1/internal", securenet.ErrRestrictedIP},
		{"HTTP_BenchmarkNetwork", "http://198.18.0.1/test", securenet.ErrRestrictedIP},
		{"HTTP_6to4RelayAnycast", "http://192.88.99.1/", securenet.ErrRestrictedIP},
		{"IPv6_NAT64WellKnown_EmbeddedMetadata", "http://[64:ff9b::a9fe:a9fe]/", securenet.ErrRestrictedIP},
		{"IPv6_NAT64LocalUse", "http://[64:ff9b:1::1]/", securenet.ErrRestrictedIP},
		// Adding a zone must not slip past the range check.
		{"IPv6_NAT64WellKnown_Zoned", "http://[64:ff9b::a9fe:a9fe%25eth0]/", securenet.ErrRestrictedIP},
		{"IPv6_6to4_Zoned", "http://[2002:a9fe:a9fe::1%25eth0]/", securenet.ErrRestrictedIP},
		{"IPv6_Documentation_Zoned", "http://[2001:db8::1%25x]/", securenet.ErrRestrictedIP},
		{"IPv6_Teredo", "http://[2001::1]/", securenet.ErrRestrictedIP},
		{"IPv6_6to4_EmbeddedLoopback", "http://[2002:7f00:1::1]/", securenet.ErrRestrictedIP},
		{"IPv6_DocumentationExtended", "http://[3fff::1]/", securenet.ErrRestrictedIP},
		{"IPv6_SegmentRoutingSID", "http://[5f00::1]/", securenet.ErrRestrictedIP},
		{"IPv6_SiteLocal_Deprecated", "http://[fec0::1]/", securenet.ErrRestrictedIP},
		{"HTTP_IPv6Multicast", "http://[ff02::1]/test", securenet.ErrRestrictedIP},
		{"IPv6_Loopback", "http://[::1]:8080/admin", securenet.ErrRestrictedIP},
		{"HTTP_LinkLocal_Metadata", "http://169.254.169.254/latest/meta-data/", securenet.ErrRestrictedIP},
		{"IPv4MappedIPv6_Loopback", "http://[::ffff:127.0.0.1]/admin", securenet.ErrRestrictedIP},
		{"Resolved_PrivateIP", "https://internal.test/api", securenet.ErrRestrictedIP},
		{"Resolved_MixedPublicAndPrivate", "https://mixed.test/api", securenet.ErrRestrictedIP},
		{"Resolved_IPv4MappedLoopback", "https://mapped.test/api", securenet.ErrRestrictedIP},
		{"Resolved_Metadata", "https://metadata.test/api", securenet.ErrRestrictedIP},
		{"Resolved_CGNAT", "https://cgnat.test/api", securenet.ErrRestrictedIP},
		{"Resolved_Benchmark", "https://benchmark.test/api", securenet.ErrRestrictedIP},
		{"Resolved_IPv6Documentation", "https://docexample.test/api", securenet.ErrRestrictedIP},

		{"FTP_InvalidScheme", "ftp://example.com/file", securenet.ErrDisallowedScheme},
		{"GCS_InvalidScheme", "gs://bucket-name/object/path", securenet.ErrDisallowedScheme},
		{"S3_InvalidScheme", "s3://my-bucket/data.json", securenet.ErrDisallowedScheme},
		{"MixedCase_GCS_InvalidScheme", "GS://bucket/object", securenet.ErrDisallowedScheme},
		{"File_InvalidScheme", "file:///etc/passwd", securenet.ErrDisallowedScheme},
		{"EmptyHost", "http://", securenet.ErrEmptyHost},
		{"OnlyScheme", "https://", securenet.ErrEmptyHost},
		{"InvalidURL", "://invalid", securenet.ErrInvalidURL},
		{"NoScheme", "example.com", securenet.ErrInvalidURL},
		{"EmptyURL", "", securenet.ErrInvalidURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := securenet.ValidateURL(ctx, tt.inputURL, securenet.WithResolver(testResolver))

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateURL_ErrorDetails(t *testing.T) {
	ctx := context.Background()

	t.Run("BlockedIPError がホストとアドレスを保持すること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api", securenet.WithResolver(testResolver))

		blocked, ok := errors.AsType[*securenet.BlockedIPError](err)
		if !ok {
			t.Fatalf("expected *BlockedIPError, got: %v", err)
		}
		if blocked.Host != "internal.test" {
			t.Errorf("blocked.Host: want %v, got %v", "internal.test", blocked.Host)
		}
		if blocked.Addr != netip.MustParseAddr("10.0.0.1") {
			t.Errorf("blocked.Addr: want %v, got %v", netip.MustParseAddr("10.0.0.1"), blocked.Addr)
		}
		if !errors.Is(blocked, securenet.ErrRestrictedIP) {
			t.Errorf("expected securenet.ErrRestrictedIP, got: %v", blocked)
		}
	})

	t.Run("SchemeError が拒否されたスキームを保持すること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "FTP://example.com/file", securenet.WithResolver(testResolver))

		se, ok := errors.AsType[*securenet.SchemeError](err)
		if !ok {
			t.Fatalf("expected *SchemeError, got: %v", err)
		}
		if se.Scheme != "ftp" {
			t.Errorf("se.Scheme: want %v, got %v", "ftp", se.Scheme)
		}
	})

	t.Run("ResolveError が元のDNSエラーをラップすること", func(t *testing.T) {
		dnsErr := &net.DNSError{Err: "server misbehaving", Name: "broken.test"}
		err := securenet.ValidateURL(ctx, "https://broken.test/api",
			securenet.WithResolver(errResolver{err: dnsErr}))

		re, ok := errors.AsType[*securenet.ResolveError](err)
		if !ok {
			t.Fatalf("expected *ResolveError, got: %v", err)
		}
		if re.Host != "broken.test" {
			t.Errorf("re.Host: want %v, got %v", "broken.test", re.Host)
		}
		if !errors.Is(err, dnsErr) {
			t.Errorf("%v is not wrapped: %v", dnsErr, err)
		}
	})

	t.Run("解決結果が空の場合に ErrNoAddresses になること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://empty.test/api",
			securenet.WithResolver(emptyResolver{}))

		if !errors.Is(err, securenet.ErrNoAddresses) {
			t.Errorf("expected securenet.ErrNoAddresses, got: %v", err)
		}
	})

	t.Run("URLError が元のパースエラーをラップすること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "://invalid", securenet.WithResolver(testResolver))

		ue, ok := errors.AsType[*securenet.URLError](err)
		if !ok {
			t.Fatalf("expected *URLError, got: %v", err)
		}
		if ue.URL != "://invalid" {
			t.Errorf("ue.URL: want %v, got %v", "://invalid", ue.URL)
		}
		if !errors.Is(err, securenet.ErrInvalidURL) {
			t.Errorf("expected securenet.ErrInvalidURL, got: %v", err)
		}
	})

	t.Run("キャンセル済み context が伝播すること", func(t *testing.T) {
		canceled, cancel := context.WithCancel(context.Background())
		cancel()

		err := securenet.ValidateURL(canceled, "https://example.com",
			securenet.WithResolver(errResolver{err: context.Canceled}))

		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
	})
}

func TestValidateURL_PolicyOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("WithAllowLoopback でループバックが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "http://127.0.0.1:8080/admin",
			securenet.WithResolver(testResolver), securenet.WithAllowLoopback())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("WithAllowPrivate でプライベートIPが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver), securenet.WithAllowPrivate())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("WithAllowedCIDRs が個別のネットワークだけを許可すること", func(t *testing.T) {
		opts := []securenet.Option{
			securenet.WithResolver(testResolver),
			securenet.WithAllowedCIDRs("10.0.0.0/8"),
		}

		if err := securenet.ValidateURL(ctx, "https://internal.test/api", opts...); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// 192.168.0.0/16, which was not allowed, is still rejected
		if err := securenet.ValidateURL(ctx, "http://192.168.1.1/", opts...); !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("expected ErrRestrictedIP, got: %v", err)
		}
	})

	t.Run("WithAllowedPrefixes が WithAllowedCIDRs と等価であること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver),
			securenet.WithAllowedPrefixes(netip.MustParsePrefix("10.0.0.0/8")))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("WithBlockedCIDRs で公開IPを追加ブロックできること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver),
			securenet.WithBlockedCIDRs("93.184.216.0/24"))
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("expected securenet.ErrRestrictedIP, got: %v", err)
		}
	})

	t.Run("WithBlockedCIDRs が既定リストを破壊しないこと", func(t *testing.T) {
		// Even after an option that adds a block has been used once,
		// the default policy of another call must not be polluted.
		_ = securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver),
			securenet.WithBlockedCIDRs("93.184.216.0/24"))

		err := securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("不正なCIDR表記は無視されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver),
			securenet.WithAllowedCIDRs("not-a-cidr", "10.0.0.0/8"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("WithAllowLinkLocal でメタデータエンドポイントが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "http://169.254.169.254/latest/meta-data/",
			securenet.WithResolver(testResolver), securenet.WithAllowLinkLocal())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ----------------------------------------------------------------------
// TestNewSafeHTTPClient: the DNS-rebinding-safe client
// ----------------------------------------------------------------------

func TestNewSafeHTTPClient(t *testing.T) {
	t.Run("ClientCreation", func(t *testing.T) {
		timeout := 10 * time.Second
		client := securenet.NewSafeHTTPClient(timeout)

		if client == nil {
			t.Fatal("client is nil")
		}
		if client.Timeout != timeout {
			t.Errorf("client.Timeout: want %v, got %v", timeout, client.Timeout)
		}
		if client.Transport == nil {
			t.Error("client.Transport is nil")
		}
		if client.CheckRedirect == nil {
			t.Error("client.CheckRedirect is nil")
		}
	})

	t.Run("ProxyFromEnvironmentDisabled", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8888")

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport is not an *http.Transport: %T", client.Transport)
		}
		if transport.Proxy != nil {
			t.Error("the environment proxy should be disabled by default")
		}
	})

	t.Run("WithProxyFromEnvironment で明示的に有効化できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithProxyFromEnvironment())
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport is not an *http.Transport: %T", client.Transport)
		}
		if transport.Proxy == nil {
			t.Error("Proxy is not set")
		}
	})

	t.Run("BlockLoopbackConnection", func(t *testing.T) {
		// httptest.NewServer listens on 127.0.0.1, so it is blocked by default
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get(server.URL)

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("expected securenet.ErrRestrictedIP, got: %v", err)
		}
	})

	t.Run("WithAllowLoopback でローカルサーバに接続できること", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithAllowLoopback())
		resp, err := client.Get(server.URL)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp.StatusCode: want %v, got %v", http.StatusOK, resp.StatusCode)
		}
	})

	t.Run("BlockPrivateIPDirectly", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get("http://192.168.10.254/test")

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("expected securenet.ErrRestrictedIP, got: %v", err)
		}
	})

	t.Run("BlockRebindingResolver", func(t *testing.T) {
		// Reproduce a resolution answer swapped for a private IP
		rebinding := fakeResolver{"rebind.test": {"127.0.0.1"}}
		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithResolver(rebinding))

		_, err := client.Get("http://rebind.test/")

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("expected securenet.ErrRestrictedIP, got: %v", err)
		}
	})

	t.Run("ContextTimeout", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(100*time.Millisecond,
			securenet.WithResolver(testResolver))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = client.Do(req)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
	})
}

func TestNewSafeTransport(t *testing.T) {
	t.Run("Transport 単体を取得できること", func(t *testing.T) {
		transport := securenet.NewSafeTransport(2*time.Second, securenet.WithAllowLoopback())

		if transport == nil {
			t.Fatal("transport is nil")
		}
		if transport.Proxy != nil {
			t.Error("transport.Proxy should be nil")
		}
		if transport.DialContext == nil {
			t.Error("transport.DialContext is nil")
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer server.Close()

		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		resp, err := client.Get(server.URL)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusTeapot {
			t.Errorf("resp.StatusCode: want %v, got %v", http.StatusTeapot, resp.StatusCode)
		}
	})

	t.Run("WithBaseTransport の設定が引き継がれること", func(t *testing.T) {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.MaxIdleConnsPerHost = 42
		base.DisableCompression = true

		transport := securenet.NewSafeTransport(time.Second, securenet.WithBaseTransport(base))

		if transport.MaxIdleConnsPerHost != 42 {
			t.Errorf("transport.MaxIdleConnsPerHost: want %v, got %v", 42, transport.MaxIdleConnsPerHost)
		}
		if !transport.DisableCompression {
			t.Error("transport.DisableCompression is false")
		}
		// Proxy and DialContext are overwritten by securenet
		if transport.Proxy != nil {
			t.Error("transport.Proxy should be nil")
		}
		if transport.DialContext == nil {
			t.Error("transport.DialContext is nil")
		}
	})

	t.Run("WithBaseTransport の DialTLSContext は無効化されること", func(t *testing.T) {
		// If DialTLSContext survives, HTTPS never calls DialContext
		// and IP validation is bypassed entirely.
		base := &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				t.Error("DialTLSContext should have been disabled")
				return nil, errors.New("must not be called")
			},
		}

		transport := securenet.NewSafeTransport(time.Second, securenet.WithBaseTransport(base))

		if transport.DialTLSContext != nil {
			t.Error("transport.DialTLSContext should be nil")
		}
		if transport.DialTLS != nil { //nolint:staticcheck // checks that the deprecated field is disabled
			t.Error("transport.DialTLS should be nil")
		}
		if transport.Dial != nil { //nolint:staticcheck // same as above
			t.Error("transport.Dial should be nil")
		}
		if transport.DialContext == nil {
			t.Error("transport.DialContext is nil")
		}
	})

	t.Run("http.DefaultTransport が差し替えられていても panic しないこと", func(t *testing.T) {
		// Instrumentation libraries and the like may replace the global DefaultTransport.
		orig := http.DefaultTransport
		http.DefaultTransport = stubRoundTripper{}
		defer func() { http.DefaultTransport = orig }()

		// A panic fails the test by itself, so no further assertion is needed.
		transport := securenet.NewSafeTransport(time.Second)
		if transport.DialContext == nil {
			t.Error("DialContext is not set")
		}
		if transport.Proxy != nil {
			t.Error("Proxy should be nil")
		}
	})

	t.Run("WithDialer が使用されること", func(t *testing.T) {
		called := false
		dialer := &net.Dialer{
			Timeout: time.Second,
			Control: func(_, _ string, _ syscall.RawConn) error {
				called = true
				return nil
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &http.Client{
			Transport: securenet.NewSafeTransport(2*time.Second,
				securenet.WithAllowLoopback(), securenet.WithDialer(dialer)),
			Timeout: 2 * time.Second,
		}
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if !called {
			t.Error("the Dialer passed to WithDialer was not used")
		}
	})

	t.Run("先頭の IP が応答しなくても次の IP へフォールバックすること", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))

		// 192.0.2.1 (TEST-NET-1) plays the black hole. No packet is actually sent;
		// ControlContext blocks until the attempt's deadline. If the deadline were not
		// split per attempt, the whole budget would be spent here and the dial would
		// fail without ever trying 127.0.0.1.
		const blackhole = "192.0.2.1"
		dialer := &net.Dialer{
			Timeout: 3 * time.Second,
			ControlContext: func(ctx context.Context, _, address string, _ syscall.RawConn) error {
				if host, _, _ := net.SplitHostPort(address); host == blackhole {
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			},
		}
		client := &http.Client{
			Transport: securenet.NewSafeTransport(3*time.Second,
				securenet.WithResolver(fakeResolver{"dualstack.test": {blackhole, "127.0.0.1"}}),
				securenet.WithAllowedCIDRs("192.0.2.0/24"),
				securenet.WithAllowLoopback(),
				securenet.WithDialer(dialer)),
			Timeout: 3 * time.Second,
		}

		resp, err := client.Get("http://dualstack.test:" + port + "/")
		if err != nil {
			t.Fatalf("did not fall back to the second IP: %v", err)
		}
		_ = resp.Body.Close()
	})
}

func TestCheckRedirect(t *testing.T) {
	newReq := func(rawURL string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return req
	}

	t.Run("https から http へのダウングレードを拒否すること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		err := client.CheckRedirect(newReq("http://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, securenet.ErrRedirectDowngrade) {
			t.Errorf("expected ErrRedirectDowngrade, got: %v", err)
		}
		dg, ok := errors.AsType[*securenet.RedirectDowngradeError](err)
		if !ok {
			t.Fatalf("expected *RedirectDowngradeError, got: %v", err)
		}
		if dg.URL != "http://example.com/next" {
			t.Errorf("dg.URL: want %v, got %v", "http://example.com/next", dg.URL)
		}
	})

	t.Run("WithAllowRedirectDowngrade で許可できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second, securenet.WithAllowRedirectDowngrade())

		err := client.CheckRedirect(newReq("http://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("同一スキームのリダイレクトは許可されること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		err := client.CheckRedirect(newReq("https://other.example/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("最大リダイレクト回数を超えると停止すること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		via := make([]*http.Request, 11)
		for i := range via {
			via[i] = newReq("https://example.com/")
		}

		err := client.CheckRedirect(newReq("https://example.com/next"), via)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		tm, ok := errors.AsType[*securenet.TooManyRedirectsError](err)
		if !ok {
			t.Fatalf("expected *TooManyRedirectsError, got: %v", err)
		}
		if tm.Max != 10 {
			t.Errorf("tm.Max: want 10, got %d", tm.Max)
		}
	})

	t.Run("WithMaxRedirects(0) でリダイレクトを禁止できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second, securenet.WithMaxRedirects(0))

		err := client.CheckRedirect(newReq("https://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, securenet.ErrTooManyRedirects) {
			t.Errorf("expected ErrTooManyRedirects, got: %v", err)
		}
	})

	t.Run("クライアント経由でも url.Error 越しに分類できること", func(t *testing.T) {
		// http.Client wraps CheckRedirect's error in a *url.Error.
		// Check that errors.Is / errors.As see through that wrapper.
		var loop *httptest.Server
		loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loop.URL+"/again", http.StatusFound)
		}))
		defer loop.Close()

		client := securenet.NewSafeHTTPClient(2*time.Second,
			securenet.WithAllowLoopback(), securenet.WithMaxRedirects(2))

		_, err := client.Get(loop.URL)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		var ue *url.Error
		if !errors.As(err, &ue) {
			t.Fatalf("not wrapped in *url.Error: %v", err)
		}
		if !errors.Is(err, securenet.ErrTooManyRedirects) {
			t.Errorf("expected ErrTooManyRedirects, got: %v", err)
		}
		tm, ok := errors.AsType[*securenet.TooManyRedirectsError](err)
		if !ok {
			t.Fatalf("expected *TooManyRedirectsError, got: %v", err)
		}
		if tm.Max != 2 {
			t.Errorf("tm.Max: want 2, got %d", tm.Max)
		}
	})

	t.Run("実際のリダイレクトを追従できること", func(t *testing.T) {
		final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer final.Close()

		entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL, http.StatusFound)
		}))
		defer entry.Close()

		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithAllowLoopback())
		resp, err := client.Get(entry.URL)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp.StatusCode: want %v, got %v", http.StatusOK, resp.StatusCode)
		}
	})
}

func TestErrorMessages(t *testing.T) {
	t.Run("BlockedIPError", func(t *testing.T) {
		err := &securenet.BlockedIPError{Host: "evil.test", Addr: netip.MustParseAddr("10.0.0.1")}
		if !strings.Contains(err.Error(), "evil.test") {
			t.Errorf("error message does not contain evil.test: %v", err)
		}
		if !strings.Contains(err.Error(), "10.0.0.1") {
			t.Errorf("error message does not contain 10.0.0.1: %v", err)
		}
	})

	t.Run("SchemeError", func(t *testing.T) {
		err := &securenet.SchemeError{Scheme: "ftp"}
		if !strings.Contains(err.Error(), "ftp") {
			t.Errorf("error message does not contain ftp: %v", err)
		}
	})

	t.Run("URLError_NilCause", func(t *testing.T) {
		err := &securenet.URLError{URL: "bad"}
		if !strings.Contains(err.Error(), "bad") {
			t.Errorf("error message does not contain bad: %v", err)
		}
		if !errors.Is(err, securenet.ErrInvalidURL) {
			t.Errorf("expected securenet.ErrInvalidURL, got: %v", err)
		}
	})

	t.Run("TooManyRedirectsError", func(t *testing.T) {
		err := &securenet.TooManyRedirectsError{Max: 7}
		if !strings.Contains(err.Error(), "7") {
			t.Errorf("error message does not contain 7: %v", err)
		}
		if !errors.Is(err, securenet.ErrTooManyRedirects) {
			t.Errorf("expected ErrTooManyRedirects, got: %v", err)
		}
	})

	t.Run("RedirectDowngradeError", func(t *testing.T) {
		err := &securenet.RedirectDowngradeError{URL: "http://example.com/next"}
		if !strings.Contains(err.Error(), "example.com") {
			t.Errorf("error message does not contain example.com: %v", err)
		}
		if !errors.Is(err, securenet.ErrRedirectDowngrade) {
			t.Errorf("expected ErrRedirectDowngrade, got: %v", err)
		}
	})

	t.Run("ResolveError", func(t *testing.T) {
		inner := errors.New("timeout")
		err := &securenet.ResolveError{Host: "slow.test", Err: inner}
		if !strings.Contains(err.Error(), "slow.test") {
			t.Errorf("error message does not contain slow.test: %v", err)
		}
		if !errors.Is(err, inner) {
			t.Errorf("expected inner, got: %v", err)
		}
	})
}

// Errors end up in logs verbatim, so the query and fragment (which can carry a
// signature or an API key) and the userinfo password must not remain in either the
// error text or its fields.
func TestErrorsRedactSecrets(t *testing.T) {
	ctx := context.Background()
	const secret = "s3cr3t"

	assertRedacted := func(t *testing.T, err error, fields ...string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		for _, s := range append([]string{err.Error()}, fields...) {
			if strings.Contains(s, secret) {
				t.Errorf("secret remains in the error: %q", s)
			}
		}
	}

	t.Run("解析できない URL の URLError", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://user:"+secret+"@public.test/%zz?sig="+secret,
			securenet.WithResolver(testResolver))

		ue, ok := errors.AsType[*securenet.URLError](err)
		if !ok {
			t.Fatalf("expected *URLError, got: %v", err)
		}
		assertRedacted(t, err, ue.URL)
		if !strings.Contains(ue.URL, "public.test") {
			t.Errorf("the host should be kept: %q", ue.URL)
		}
		if _, ok := errors.AsType[*url.Error](err); !ok {
			t.Errorf("the original *url.Error should be extractable: %v", err)
		}
	})

	t.Run("ホストが空のエラー", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https:///path?token="+secret+"#"+secret,
			securenet.WithResolver(testResolver))

		if !errors.Is(err, securenet.ErrEmptyHost) {
			t.Fatalf("expected ErrEmptyHost, got: %v", err)
		}
		assertRedacted(t, err)
	})

	t.Run("ダウングレードしたリダイレクト先", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)
		next, err := http.NewRequest(http.MethodGet,
			"http://user:"+secret+"@example.com/next?X-Goog-Signature="+secret+"#"+secret, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		prev, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = client.CheckRedirect(next, []*http.Request{prev})

		dg, ok := errors.AsType[*securenet.RedirectDowngradeError](err)
		if !ok {
			t.Fatalf("expected *RedirectDowngradeError, got: %v", err)
		}
		assertRedacted(t, err, dg.URL)
		if want := "http://user:xxxxx@example.com/next?REDACTED"; dg.URL != want {
			t.Errorf("dg.URL: want %v, got %v", want, dg.URL)
		}
	})
}
