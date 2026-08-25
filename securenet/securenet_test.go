package securenet_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/shouni/netarmor/securenet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			assert.Equal(t, tt.want, securenet.IsSecureServiceURL(tt.inputURL), "URL: %s", tt.inputURL)
		})
	}
}

// ----------------------------------------------------------------------
// TestValidateURL: SSRF対策のURL検証テスト
// ----------------------------------------------------------------------

func TestValidateURL(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		inputURL string
		wantErr  error // nil なら成功を期待
	}{
		{"CloudStorage_GCS", "gs://bucket-name/object/path", nil},
		{"CloudStorage_S3", "s3://my-bucket/data.json", nil},
		{"MixedCase_Scheme_GCS", "GS://bucket/object", nil},
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
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestValidateURL_ErrorDetails(t *testing.T) {
	ctx := context.Background()

	t.Run("BlockedIPError がホストとアドレスを保持すること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api", securenet.WithResolver(testResolver))

		var blocked *securenet.BlockedIPError
		require.ErrorAs(t, err, &blocked)
		assert.Equal(t, "internal.test", blocked.Host)
		assert.Equal(t, netip.MustParseAddr("10.0.0.1"), blocked.Addr)
		assert.ErrorIs(t, blocked, securenet.ErrRestrictedIP)
	})

	t.Run("SchemeError が拒否されたスキームを保持すること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "FTP://example.com/file", securenet.WithResolver(testResolver))

		var se *securenet.SchemeError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, "ftp", se.Scheme)
	})

	t.Run("ResolveError が元のDNSエラーをラップすること", func(t *testing.T) {
		dnsErr := &net.DNSError{Err: "server misbehaving", Name: "broken.test"}
		err := securenet.ValidateURL(ctx, "https://broken.test/api",
			securenet.WithResolver(errResolver{err: dnsErr}))

		var re *securenet.ResolveError
		require.ErrorAs(t, err, &re)
		assert.Equal(t, "broken.test", re.Host)
		assert.ErrorIs(t, err, dnsErr)
	})

	t.Run("解決結果が空の場合に ErrNoAddresses になること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://empty.test/api",
			securenet.WithResolver(emptyResolver{}))

		assert.ErrorIs(t, err, securenet.ErrNoAddresses)
	})

	t.Run("URLError が元のパースエラーをラップすること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "://invalid", securenet.WithResolver(testResolver))

		var ue *securenet.URLError
		require.ErrorAs(t, err, &ue)
		assert.Equal(t, "://invalid", ue.URL)
		assert.ErrorIs(t, err, securenet.ErrInvalidURL)
	})

	t.Run("キャンセル済み context が伝播すること", func(t *testing.T) {
		canceled, cancel := context.WithCancel(context.Background())
		cancel()

		err := securenet.ValidateURL(canceled, "https://example.com",
			securenet.WithResolver(errResolver{err: context.Canceled}))

		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestValidateURL_PolicyOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("WithAllowLoopback でループバックが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "http://127.0.0.1:8080/admin",
			securenet.WithResolver(testResolver), securenet.WithAllowLoopback())
		assert.NoError(t, err)
	})

	t.Run("WithAllowPrivate でプライベートIPが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver), securenet.WithAllowPrivate())
		assert.NoError(t, err)
	})

	t.Run("WithAllowedCIDRs が個別のネットワークだけを許可すること", func(t *testing.T) {
		opts := []securenet.Option{
			securenet.WithResolver(testResolver),
			securenet.WithAllowedCIDRs("10.0.0.0/8"),
		}

		assert.NoError(t, securenet.ValidateURL(ctx, "https://internal.test/api", opts...))
		// 許可していない 192.168.0.0/16 は引き続き拒否される
		assert.ErrorIs(t, securenet.ValidateURL(ctx, "http://192.168.1.1/", opts...),
			securenet.ErrRestrictedIP)
	})

	t.Run("WithAllowedPrefixes が WithAllowedCIDRs と等価であること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver),
			securenet.WithAllowedPrefixes(netip.MustParsePrefix("10.0.0.0/8")))
		assert.NoError(t, err)
	})

	t.Run("WithBlockedCIDRs で公開IPを追加ブロックできること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver),
			securenet.WithBlockedCIDRs("93.184.216.0/24"))
		assert.ErrorIs(t, err, securenet.ErrRestrictedIP)
	})

	t.Run("WithBlockedCIDRs が既定リストを破壊しないこと", func(t *testing.T) {
		// 追加ブロックを行ったオプションを一度使った後でも、
		// 別の呼び出しの既定ポリシーが汚染されていないことを確認する。
		_ = securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver),
			securenet.WithBlockedCIDRs("93.184.216.0/24"))

		err := securenet.ValidateURL(ctx, "https://example.com/api",
			securenet.WithResolver(testResolver))
		assert.NoError(t, err)
	})

	t.Run("不正なCIDR表記は無視されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "https://internal.test/api",
			securenet.WithResolver(testResolver),
			securenet.WithAllowedCIDRs("not-a-cidr", "10.0.0.0/8"))
		assert.NoError(t, err)
	})

	t.Run("WithAllowLinkLocal でメタデータエンドポイントが許可されること", func(t *testing.T) {
		err := securenet.ValidateURL(ctx, "http://169.254.169.254/latest/meta-data/",
			securenet.WithResolver(testResolver), securenet.WithAllowLinkLocal())
		assert.NoError(t, err)
	})
}

// ----------------------------------------------------------------------
// TestNewSafeHTTPClient: DNS Rebinding対策クライアントのテスト
// ----------------------------------------------------------------------

func TestNewSafeHTTPClient(t *testing.T) {
	t.Run("ClientCreation", func(t *testing.T) {
		timeout := 10 * time.Second
		client := securenet.NewSafeHTTPClient(timeout)

		require.NotNil(t, client)
		assert.Equal(t, timeout, client.Timeout)
		assert.NotNil(t, client.Transport)
		assert.NotNil(t, client.CheckRedirect)
	})

	t.Run("ProxyFromEnvironmentDisabled", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8888")

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		transport, ok := client.Transport.(*http.Transport)

		require.True(t, ok)
		assert.Nil(t, transport.Proxy)
	})

	t.Run("WithProxyFromEnvironment で明示的に有効化できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithProxyFromEnvironment())
		transport, ok := client.Transport.(*http.Transport)

		require.True(t, ok)
		assert.NotNil(t, transport.Proxy)
	})

	t.Run("BlockLoopbackConnection", func(t *testing.T) {
		// httptest.NewServer は 127.0.0.1 で起動するため、既定ではブロックされる
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get(server.URL)

		require.Error(t, err)
		assert.ErrorIs(t, err, securenet.ErrRestrictedIP)
	})

	t.Run("WithAllowLoopback でローカルサーバに接続できること", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithAllowLoopback())
		resp, err := client.Get(server.URL)

		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("BlockPrivateIPDirectly", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get("http://192.168.10.254/test")

		require.Error(t, err)
		assert.ErrorIs(t, err, securenet.ErrRestrictedIP)
	})

	t.Run("BlockRebindingResolver", func(t *testing.T) {
		// 名前解決の結果がプライベートIPに差し替えられた状況を再現する
		rebinding := fakeResolver{"rebind.test": {"127.0.0.1"}}
		client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithResolver(rebinding))

		_, err := client.Get("http://rebind.test/")

		require.Error(t, err)
		assert.ErrorIs(t, err, securenet.ErrRestrictedIP)
	})

	t.Run("ContextTimeout", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(100*time.Millisecond,
			securenet.WithResolver(testResolver))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		_, err = client.Do(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestNewSafeTransport(t *testing.T) {
	t.Run("Transport 単体を取得できること", func(t *testing.T) {
		transport := securenet.NewSafeTransport(2*time.Second, securenet.WithAllowLoopback())

		require.NotNil(t, transport)
		assert.Nil(t, transport.Proxy)
		assert.NotNil(t, transport.DialContext)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		defer server.Close()

		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		resp, err := client.Get(server.URL)

		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	})

	t.Run("WithBaseTransport の設定が引き継がれること", func(t *testing.T) {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.MaxIdleConnsPerHost = 42
		base.DisableCompression = true

		transport := securenet.NewSafeTransport(time.Second, securenet.WithBaseTransport(base))

		assert.Equal(t, 42, transport.MaxIdleConnsPerHost)
		assert.True(t, transport.DisableCompression)
		// Proxy と DialContext は securenet 側で上書きされる
		assert.Nil(t, transport.Proxy)
		assert.NotNil(t, transport.DialContext)
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

		assert.Nil(t, transport.DialTLSContext)
		assert.Nil(t, transport.DialTLS)
		assert.Nil(t, transport.Dial)
		assert.NotNil(t, transport.DialContext)
	})

	t.Run("http.DefaultTransport が差し替えられていても panic しないこと", func(t *testing.T) {
		// 計装ライブラリ等がグローバルの DefaultTransport を差し替えることがある。
		orig := http.DefaultTransport
		http.DefaultTransport = stubRoundTripper{}
		defer func() { http.DefaultTransport = orig }()

		require.NotPanics(t, func() {
			transport := securenet.NewSafeTransport(time.Second)
			assert.NotNil(t, transport.DialContext)
			assert.Nil(t, transport.Proxy)
		})
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
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.True(t, called, "WithDialer で渡した Dialer が使われていません")
	})
}

func TestCheckRedirect(t *testing.T) {
	newReq := func(rawURL string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		return req
	}

	t.Run("https から http へのダウングレードを拒否すること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		err := client.CheckRedirect(newReq("http://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "downgrade")
	})

	t.Run("WithAllowRedirectDowngrade で許可できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second, securenet.WithAllowRedirectDowngrade())

		err := client.CheckRedirect(newReq("http://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		assert.NoError(t, err)
	})

	t.Run("同一スキームのリダイレクトは許可されること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		err := client.CheckRedirect(newReq("https://other.example/next"),
			[]*http.Request{newReq("https://example.com/")})

		assert.NoError(t, err)
	})

	t.Run("最大リダイレクト回数を超えると停止すること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second)

		via := make([]*http.Request, 11)
		for i := range via {
			via[i] = newReq("https://example.com/")
		}

		err := client.CheckRedirect(newReq("https://example.com/next"), via)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stopped after 10 redirects")
	})

	t.Run("WithMaxRedirects(0) でリダイレクトを禁止できること", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(time.Second, securenet.WithMaxRedirects(0))

		err := client.CheckRedirect(newReq("https://example.com/next"),
			[]*http.Request{newReq("https://example.com/")})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "stopped after 0 redirects")
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

		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestErrorMessages(t *testing.T) {
	t.Run("BlockedIPError", func(t *testing.T) {
		err := &securenet.BlockedIPError{Host: "evil.test", Addr: netip.MustParseAddr("10.0.0.1")}
		assert.Contains(t, err.Error(), "evil.test")
		assert.Contains(t, err.Error(), "10.0.0.1")
	})

	t.Run("SchemeError", func(t *testing.T) {
		err := &securenet.SchemeError{Scheme: "ftp"}
		assert.Contains(t, err.Error(), "ftp")
	})

	t.Run("URLError_NilCause", func(t *testing.T) {
		err := &securenet.URLError{URL: "bad"}
		assert.Contains(t, err.Error(), "bad")
		assert.ErrorIs(t, err, securenet.ErrInvalidURL)
	})

	t.Run("ResolveError", func(t *testing.T) {
		inner := errors.New("timeout")
		err := &securenet.ResolveError{Host: "slow.test", Err: inner}
		assert.Contains(t, err.Error(), "slow.test")
		assert.ErrorIs(t, err, inner)
	})
}
