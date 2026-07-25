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

// exampleResolver は例示を決定的にするための固定リゾルバです。
// 実際のコードではリゾルバを指定せず、既定の net.DefaultResolver を使用します。
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

	// 公開 IP に解決されるホストは許可される
	fmt.Println(securenet.ValidateURL(ctx, "https://api.example.com/v1",
		securenet.WithResolver(demoResolver)))

	// プライベート IP に解決されるホストは拒否される
	fmt.Println(securenet.ValidateURL(ctx, "https://internal.example.com/admin",
		securenet.WithResolver(demoResolver)))

	// Output:
	// <nil>
	// securenet: restricted network: host "internal.example.com" resolved to 10.0.0.5
}

// 検証エラーは errors.Is / errors.As で分類できます。
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

	// クラウドのメタデータエンドポイントは DialContext 層で遮断される
	_, err := client.Get("http://169.254.169.254/latest/meta-data/")

	fmt.Println("blocked:", errors.Is(err, securenet.ErrRestrictedIP))
	// Output: blocked: true
}

// テストではローカルサーバへの接続を明示的に許可できます。
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

// 独自の *http.Client を組み立てたい場合は Transport だけを取得します。
func ExampleNewSafeTransport() {
	transport := securenet.NewSafeTransport(10 * time.Second)

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		// cookiejar やリダイレクトポリシーを独自に設定できる
	}

	_, err := client.Get("http://10.0.0.1/internal")
	fmt.Println("blocked:", errors.Is(err, securenet.ErrRestrictedIP))
	// Output: blocked: true
}

// 社内ネットワークへのアクセスが必要な場合は、範囲を限定して許可します。
func ExampleWithAllowedCIDRs() {
	ctx := context.Background()

	opts := []securenet.Option{
		securenet.WithResolver(demoResolver),
		securenet.WithAllowedCIDRs("10.0.0.0/8"),
	}

	// 許可した範囲は通る
	fmt.Println(securenet.ValidateURL(ctx, "https://internal.example.com/", opts...))

	// 許可していない範囲は引き続き拒否される
	err := securenet.ValidateURL(ctx, "http://192.168.1.1/", opts...)
	fmt.Println("still blocked:", errors.Is(err, securenet.ErrRestrictedIP))

	// Output:
	// <nil>
	// still blocked: true
}

func ExampleIsSecureServiceURL() {
	// 名前解決を伴わない、設定値の妥当性チェック
	fmt.Println(securenet.IsSecureServiceURL("https://api.example.com"))
	fmt.Println(securenet.IsSecureServiceURL("http://localhost:8080"))
	fmt.Println(securenet.IsSecureServiceURL("http://api.example.com"))

	// Output:
	// true
	// true
	// false
}
