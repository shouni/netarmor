package securenet_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shouni/netarmor/securenet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------
// TestIsSecureServiceURL: HTTPS/ローカル環境判定のテスト
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
			got := securenet.IsSecureServiceURL(tt.inputURL)
			assert.Equal(t, tt.want, got, "URL: %s", tt.inputURL)
		})
	}
}

// ----------------------------------------------------------------------
// TestIsSafeURL: SSRF対策のURL検証テスト
// ----------------------------------------------------------------------

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		name       string
		inputURL   string
		wantSafe   bool
		wantErrMsg string
	}{
		{"CloudStorage_GCS", "gs://bucket-name/object/path", true, ""},
		{"CloudStorage_S3", "s3://my-bucket/data.json", true, ""},
		{"HTTPS_PublicDomain", "https://example.com/api", true, ""},
		{"HTTP_PublicDomain", "http://example.com/data", true, ""},
		{"HTTP_Localhost_Restricted", "http://localhost/admin", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_127.0.0.1_Restricted", "http://127.0.0.1:8080/secret", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_PrivateIP_10.0.0.1", "http://10.0.0.1/internal", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_PrivateIP_192.168.1.1", "http://192.168.1.1/router", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_UnspecifiedIP", "http://0.0.0.0/admin", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_CGNAT", "http://100.64.0.1/internal", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_BenchmarkNetwork", "http://198.18.0.1/test", false, "制限されたネットワークへのアクセスを検知"},
		{"HTTP_IPv6Multicast", "http://[ff02::1]/test", false, "制限されたネットワークへのアクセスを検知"},
		{"FTP_InvalidScheme", "ftp://example.com/file", false, "不許可スキーム"},
		{"EmptyHost", "http://", false, "ホストが空です"},
		{"InvalidURL", "://invalid", false, "URLパース失敗"},
		{"NoScheme", "example.com", false, "URLパース失敗"},
		{"MixedCase_Scheme_GCS", "GS://bucket/object", true, ""},
		{"IPv6_Loopback", "http://[::1]:8080/admin", false, "制限されたネットワークへのアクセスを検知"},
		{"OnlyScheme", "https://", false, "ホストが空です"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safe, err := securenet.IsSafeURL(tt.inputURL)

			if tt.wantSafe {
				assert.NoError(t, err)
				assert.True(t, safe)
			} else {
				assert.Error(t, err)
				assert.False(t, safe)
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
			}
		})
	}
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
	})

	t.Run("ProxyFromEnvironmentDisabled", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:8888")
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8888")

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		transport, ok := client.Transport.(*http.Transport)

		require.True(t, ok)
		assert.Nil(t, transport.Proxy)
	})

	t.Run("BlockLoopbackConnection", func(t *testing.T) {
		// httptest.NewServer は 127.0.0.1 で起動するため、NewSafeHTTPClient でブロックされることを確認する
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := securenet.NewSafeHTTPClient(2 * time.Second)
		_, err := client.Get(server.URL)

		// ループバックIPなので、接続前にエラーになるはず
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "restricted IP detected")
	})

	t.Run("BlockPrivateIPDirectly", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(2 * time.Second)

		// 存在しないプライベートIPへのリクエスト
		_, err := client.Get("http://192.168.10.254/test")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "restricted IP detected")
	})

	t.Run("ContextTimeout", func(t *testing.T) {
		client := securenet.NewSafeHTTPClient(100 * time.Millisecond)

		// 既にキャンセルされたコンテキストでリクエスト
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com", nil)
		_, err := client.Do(req)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})
}
