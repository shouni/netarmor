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

// stubRoundTripper は *http.Transport ではない http.DefaultTransport を再現します。
type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("stub round tripper")
}

// fakeResolver は実 DNS に依存せずに名前解決を再現するテスト用リゾルバです。
// これによりテストはオフラインでも決定的に動作します。
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

// errResolver は常に解決に失敗するリゾルバです。
type errResolver struct{ err error }

func (e errResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, e.err
}

// emptyResolver は解決に成功するが結果が空のリゾルバです。
type emptyResolver struct{}

func (emptyResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, nil
}

var testResolver = fakeResolver{
	"localhost":       {"127.0.0.1"},
	"example.com":     {"93.184.216.34"},
	"public.test":     {"93.184.216.34", "2606:2800:220:1::1"},
	"internal.test":   {"10.0.0.1"},
	"mixed.test":      {"93.184.216.34", "192.168.1.1"}, // 1つでも制限対象なら全体を拒否
	"mapped.test":     {"::ffff:127.0.0.1"},             // IPv4-mapped IPv6 による回避の試み
	"metadata.test":   {"169.254.169.254"},
	"cgnat.test":      {"100.64.0.1"},
	"benchmark.test":  {"198.18.0.1"},
	"docexample.test": {"2001:db8::1"},
}

// ----------------------------------------------------------------------
// TestIsSecureServiceURL: HTTPS/ローカル環境判定のテスト（名前解決なし）
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
				t.Errorf("URL %q: 期待 %v, 実績 %v", tt.inputURL, tt.want, got)
			}
		})
	}
}

// ----------------------------------------------------------------------
// TestValidateURL: SSRF 対策の URL 検証テスト
// ----------------------------------------------------------------------

func TestValidateURL(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		inputURL string
		wantErr  error // nil なら成功を期待
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
					t.Errorf("期待しないエラーが発生しました: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("エラーを期待していましたが nil でした")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("%v を期待していましたが、異なります: %v", tt.wantErr, err)
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
			t.Fatalf("*BlockedIPError を期待していましたが、異なります: %v", err)
		}
		if blocked.Host != "internal.test" {
			t.Errorf("blocked.Host が不正です: 期待 %v, 実績 %v", "internal.test", blocked.Host)
		}
		if blocked.Addr != netip.MustParseAddr("10.0.0.1") {
			t.Errorf("blocked.Addr が不正です: 期待 %v, 実績 %v", netip.MustParseAddr("10.0.0.1"), blocked.Addr)
		}
		if !errors.Is(blocked, securenet.ErrRestrictedIP) {
			t.Errorf("securenet.ErrRestrictedIP を期待していましたが、異なります: %v", blocked)
		}
	})

	t.Run("SchemeError が拒否されたスキームを保持すること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "FTP://example.com/file", securenet.WithResolver(testResolver))

		se, ok := errors.AsType[*securenet.SchemeError](err)
		if !ok {
			t.Fatalf("*SchemeError を期待していましたが、異なります: %v", err)
		}
		if se.Scheme != "ftp" {
			t.Errorf("se.Scheme が不正です: 期待 %v, 実績 %v", "ftp", se.Scheme)
		}
	})

	t.Run("ResolveError が元のDNSエラーをラップすること", func(t *testing.T) {
		dnsErr := &net.DNSError{Err: "server misbehaving", Name: "broken.test"}
		err := securenet.ValidateURL(ctx, "https://broken.test/api",
			securenet.WithResolver(errResolver{err: dnsErr}))

		re, ok := errors.AsType[*securenet.ResolveError](err)
		if !ok {
			t.Fatalf("*ResolveError を期待していましたが、異なります: %v", err)
		}
		if re.Host != "broken.test" {
			t.Errorf("re.Host が不正です: 期待 %v, 実績 %v", "broken.test", re.Host)
		}
		if !errors.Is(err, dnsErr) {
			t.Errorf("%v がラップされていません: %v", dnsErr, err)
		}
	})

	t.Run("解決結果が空の場合に ErrNoAddresses になること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://empty.test/api",
			securenet.WithResolver(emptyResolver{}))

		if !errors.Is(err, securenet.ErrNoAddresses) {
			t.Errorf("securenet.ErrNoAddresses を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("URLError が元のパースエラーをラップすること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "://invalid", securenet.WithResolver(testResolver))

		ue, ok := errors.AsType[*securenet.URLError](err)
		if !ok {
			t.Fatalf("*URLError を期待していましたが、異なります: %v", err)
		}
		if ue.URL != "://invalid" {
			t.Errorf("ue.URL が不正です: 期待 %v, 実績 %v", "://invalid", ue.URL)
		}
		if !errors.Is(err, securenet.ErrInvalidURL) {
			t.Errorf("securenet.ErrInvalidURL を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("キャンセル済み context が伝播すること", func(t *testing.T) {
		canceled, cancel := context.WithCancel(context.Background())
		cancel()

		err := securenet.ValidateURL(canceled, "https://example.com",
			securenet.WithResolver(errResolver{err: context.Canceled}))

		if !errors.Is(err, context.Canceled) {
			t.Errorf("context.Canceled を期待していましたが、異なります: %v", err)
		}
	})
}

func TestValidateURL_PolicyOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("WithAllowLoopback でループバックが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "http://127.0.0.1:8080/admin",
			securenet.WithResolver(testResolver), securenet.WithAllowLoopback())
		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})

	t.Run("WithAllowPrivate でプライベートIPが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver), securenet.WithAllowPrivate())
		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})

	t.Run("WithAllowedCIDRs が個別のネットワークだけを許可すること", func(t *testing.T) {
		opts := []securenet.Option{
			securenet.WithResolver(testResolver),
			securenet.WithAllowedCIDRs("10.0.0.0/8"),
		}

		if err := securenet.ValidateURL(ctx, "https://internal.test/api", opts...); err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
		// 許可していない 192.168.0.0/16 は引き続き拒否される
		if err := securenet.ValidateURL(ctx, "http://192.168.1.1/", opts...); !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("ErrRestrictedIP を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("WithAllowedPrefixes が WithAllowedCIDRs と等価であること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver),
			securenet.WithAllowedPrefixes(netip.MustParsePrefix("10.0.0.0/8")))
		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})

	t.Run("WithBlockedCIDRs で公開IPを追加ブロックできること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver),
			securenet.WithBlockedCIDRs("93.184.216.0/24"))
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("securenet.ErrRestrictedIP を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("WithBlockedCIDRs が既定リストを破壊しないこと", func(t *testing.T) {
		// 追加ブロックを行ったオプションを一度使った後でも、
		// 別の呼び出しの既定ポリシーが汚染されていないことを確認する。
		_ = securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver),
			securenet.WithBlockedCIDRs("93.184.216.0/24"))

		err := securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver))
		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})

	t.Run("不正なCIDR表記は無視されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver),
			securenet.WithAllowedCIDRs("not-a-cidr", "10.0.0.0/8"))
		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})

	t.Run("WithAllowLinkLocal でメタデータエンドポイントが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "http://169.254.169.254/latest/meta-data/",
			securenet.WithResolver(testResolver), securenet.WithAllowLinkLocal())
		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})
}

// ----------------------------------------------------------------------
// TestNewSafeHTTPClient: DNS Rebinding 対策クライアントのテスト
// ----------------------------------------------------------------------

func TestNewSafeHTTPClient(t *testing.T) {
	t.Run("ClientCreation", func(t *testing.T) {
		timeout := 10 * time.Second
		client := securenet.NewSafeHTTPClient(timeout)

		if client == nil {
			t.Fatal("client が nil です")
		}
		if client.Timeout != timeout {
			t.Errorf("client.Timeout が不正です: 期待 %v, 実績 %v", timeout, client.Timeout)
		}
		if client.Transport == nil {
			t.Error("client.Transport が nil です")
		}
		if client.CheckRedirect == nil {
			t.Error("client.CheckRedirect が nil です")
		}
	})

	t.Run("ProxyFromEnvironmentDisabled", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8888")

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport が *http.Transport ではありません: %T", client.Transport)
		}
		if transport.Proxy != nil {
			t.Error("環境変数のプロキシは既定で無効であるべきです")
		}
	})

	t.Run("WithProxyFromEnvironment で明示的に有効化できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithProxyFromEnvironment())
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport が *http.Transport ではありません: %T", client.Transport)
		}
		if transport.Proxy == nil {
			t.Error("Proxy が設定されていません")
		}
	})

	t.Run("BlockLoopbackConnection", func(t *testing.T) {
		// httptest.NewServer は 127.0.0.1 で起動するため、既定ではブロックされる
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get(server.URL)

		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("securenet.ErrRestrictedIP を期待していましたが、異なります: %v", err)
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
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp.StatusCode が不正です: 期待 %v, 実績 %v", http.StatusOK, resp.StatusCode)
		}
	})

	t.Run("BlockPrivateIPDirectly", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get("http://192.168.10.254/test")

		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("securenet.ErrRestrictedIP を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("BlockRebindingResolver", func(t *testing.T) {
		// 名前解決の結果がプライベート IP に差し替えられた状況を再現する
		rebinding := fakeResolver{"rebind.test": {"127.0.0.1"}}
		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithResolver(rebinding))

		_, err := client.Get("http://rebind.test/")

		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		if !errors.Is(err, securenet.ErrRestrictedIP) {
			t.Errorf("securenet.ErrRestrictedIP を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("ContextTimeout", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(100*time.Millisecond,
			securenet.WithResolver(testResolver))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}

		_, err = client.Do(req)
		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("context.Canceled を期待していましたが、異なります: %v", err)
		}
	})
}

func TestNewSafeTransport(t *testing.T) {
	t.Run("Transport 単体を取得できること", func(t *testing.T) {
		transport := securenet.NewSafeTransport(2*time.Second, securenet.WithAllowLoopback())

		if transport == nil {
			t.Fatal("transport が nil です")
		}
		if transport.Proxy != nil {
			t.Error("transport.Proxy は nil であるべきです")
		}
		if transport.DialContext == nil {
			t.Error("transport.DialContext が nil です")
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer server.Close()

		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		resp, err := client.Get(server.URL)

		if err != nil {
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusTeapot {
			t.Errorf("resp.StatusCode が不正です: 期待 %v, 実績 %v", http.StatusTeapot, resp.StatusCode)
		}
	})

	t.Run("WithBaseTransport の設定が引き継がれること", func(t *testing.T) {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.MaxIdleConnsPerHost = 42
		base.DisableCompression = true

		transport := securenet.NewSafeTransport(time.Second, securenet.WithBaseTransport(base))

		if transport.MaxIdleConnsPerHost != 42 {
			t.Errorf("transport.MaxIdleConnsPerHost が不正です: 期待 %v, 実績 %v", 42, transport.MaxIdleConnsPerHost)
		}
		if !transport.DisableCompression {
			t.Error("transport.DisableCompression が false です")
		}
		// Proxy と DialContext は securenet 側で上書きされる
		if transport.Proxy != nil {
			t.Error("transport.Proxy は nil であるべきです")
		}
		if transport.DialContext == nil {
			t.Error("transport.DialContext が nil です")
		}
	})

	t.Run("WithBaseTransport の DialTLSContext は無効化されること", func(t *testing.T) {
		// DialTLSContext が生き残ると HTTPS で DialContext が呼ばれず、
		// IP 検証が丸ごと迂回される。
		base := &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				t.Error("DialTLSContext は無効化されるべきです")
				return nil, errors.New("must not be called")
			},
		}

		transport := securenet.NewSafeTransport(time.Second, securenet.WithBaseTransport(base))

		if transport.DialTLSContext != nil {
			t.Error("transport.DialTLSContext は nil であるべきです")
		}
		if transport.DialTLS != nil { //nolint:staticcheck // 非推奨フィールドが無効化されていることの確認
			t.Error("transport.DialTLS は nil であるべきです")
		}
		if transport.Dial != nil { //nolint:staticcheck // 同上
			t.Error("transport.Dial は nil であるべきです")
		}
		if transport.DialContext == nil {
			t.Error("transport.DialContext が nil です")
		}
	})

	t.Run("http.DefaultTransport が差し替えられていても panic しないこと", func(t *testing.T) {
		// 計装ライブラリ等がグローバルの DefaultTransport を差し替えることがある。
		orig := http.DefaultTransport
		http.DefaultTransport = stubRoundTripper{}
		defer func() { http.DefaultTransport = orig }()

		// panic した場合はテスト自体が失敗するため、追加のアサーションは不要。
		transport := securenet.NewSafeTransport(time.Second)
		if transport.DialContext == nil {
			t.Error("DialContext が設定されていません")
		}
		if transport.Proxy != nil {
			t.Error("Proxy は nil であるべきです")
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
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if !called {
			t.Error("WithDialer で渡した Dialer が使われていません")
		}
	})
}

func TestCheckRedirect(t *testing.T) {
	newReq := func(rawURL string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		return req
	}

	t.Run("https から http へのダウングレードを拒否すること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		err := client.CheckRedirect(newReq("http://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		if !errors.Is(err, securenet.ErrRedirectDowngrade) {
			t.Errorf("ErrRedirectDowngrade を期待していましたが、異なります: %v", err)
		}
		dg, ok := errors.AsType[*securenet.RedirectDowngradeError](err)
		if !ok {
			t.Fatalf("*RedirectDowngradeError を期待していましたが、異なります: %v", err)
		}
		if dg.URL != "http://example.com/next" {
			t.Errorf("dg.URL が不正です: 期待 %v, 実績 %v", "http://example.com/next", dg.URL)
		}
	})

	t.Run("WithAllowRedirectDowngrade で許可できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second, securenet.WithAllowRedirectDowngrade())

		err := client.CheckRedirect(newReq("http://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})

	t.Run("同一スキームのリダイレクトは許可されること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		err := client.CheckRedirect(newReq("https://other.example/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
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
			t.Fatal("エラーを期待していましたが nil でした")
		}
		tm, ok := errors.AsType[*securenet.TooManyRedirectsError](err)
		if !ok {
			t.Fatalf("*TooManyRedirectsError を期待していましたが、異なります: %v", err)
		}
		if tm.Max != 10 {
			t.Errorf("tm.Max が不正です: 期待 10, 実績 %d", tm.Max)
		}
	})

	t.Run("WithMaxRedirects(0) でリダイレクトを禁止できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second, securenet.WithMaxRedirects(0))

		err := client.CheckRedirect(newReq("https://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		if !errors.Is(err, securenet.ErrTooManyRedirects) {
			t.Errorf("ErrTooManyRedirects を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("クライアント経由でも url.Error 越しに分類できること", func(t *testing.T) {
		// http.Client は CheckRedirect のエラーを *url.Error に包んで返す。
		// errors.Is / errors.As がその包みを透過することを確認する。
		var loop *httptest.Server
		loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loop.URL+"/again", http.StatusFound)
		}))
		defer loop.Close()

		client := securenet.NewSafeHTTPClient(2*time.Second,
			securenet.WithAllowLoopback(), securenet.WithMaxRedirects(2))

		_, err := client.Get(loop.URL)
		if err == nil {
			t.Fatal("エラーを期待していましたが nil でした")
		}
		var ue *url.Error
		if !errors.As(err, &ue) {
			t.Fatalf("*url.Error に包まれていません: %v", err)
		}
		if !errors.Is(err, securenet.ErrTooManyRedirects) {
			t.Errorf("ErrTooManyRedirects を期待していましたが、異なります: %v", err)
		}
		tm, ok := errors.AsType[*securenet.TooManyRedirectsError](err)
		if !ok {
			t.Fatalf("*TooManyRedirectsError を期待していましたが、異なります: %v", err)
		}
		if tm.Max != 2 {
			t.Errorf("tm.Max が不正です: 期待 2, 実績 %d", tm.Max)
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
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp.StatusCode が不正です: 期待 %v, 実績 %v", http.StatusOK, resp.StatusCode)
		}
	})
}

func TestErrorMessages(t *testing.T) {
	t.Run("BlockedIPError", func(t *testing.T) {
		err := &securenet.BlockedIPError{Host: "evil.test", Addr: netip.MustParseAddr("10.0.0.1")}
		if !strings.Contains(err.Error(), "evil.test") {
			t.Errorf("エラーメッセージに evil.test が含まれていません: %v", err)
		}
		if !strings.Contains(err.Error(), "10.0.0.1") {
			t.Errorf("エラーメッセージに 10.0.0.1 が含まれていません: %v", err)
		}
	})

	t.Run("SchemeError", func(t *testing.T) {
		err := &securenet.SchemeError{Scheme: "ftp"}
		if !strings.Contains(err.Error(), "ftp") {
			t.Errorf("エラーメッセージに ftp が含まれていません: %v", err)
		}
	})

	t.Run("URLError_NilCause", func(t *testing.T) {
		err := &securenet.URLError{URL: "bad"}
		if !strings.Contains(err.Error(), "bad") {
			t.Errorf("エラーメッセージに bad が含まれていません: %v", err)
		}
		if !errors.Is(err, securenet.ErrInvalidURL) {
			t.Errorf("securenet.ErrInvalidURL を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("TooManyRedirectsError", func(t *testing.T) {
		err := &securenet.TooManyRedirectsError{Max: 7}
		if !strings.Contains(err.Error(), "7") {
			t.Errorf("エラーメッセージに 7 が含まれていません: %v", err)
		}
		if !errors.Is(err, securenet.ErrTooManyRedirects) {
			t.Errorf("ErrTooManyRedirects を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("RedirectDowngradeError", func(t *testing.T) {
		err := &securenet.RedirectDowngradeError{URL: "http://example.com/next"}
		if !strings.Contains(err.Error(), "example.com") {
			t.Errorf("エラーメッセージに example.com が含まれていません: %v", err)
		}
		if !errors.Is(err, securenet.ErrRedirectDowngrade) {
			t.Errorf("ErrRedirectDowngrade を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("ResolveError", func(t *testing.T) {
		inner := errors.New("timeout")
		err := &securenet.ResolveError{Host: "slow.test", Err: inner}
		if !strings.Contains(err.Error(), "slow.test") {
			t.Errorf("エラーメッセージに slow.test が含まれていません: %v", err)
		}
		if !errors.Is(err, inner) {
			t.Errorf("inner を期待していましたが、異なります: %v", err)
		}
	})
}
