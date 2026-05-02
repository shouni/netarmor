package securenet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
	SchemeGCS   = "gs"
	SchemeS3    = "s3"

	defaultDNSLookupTimeout = 5 * time.Second
)

// localdevHostnames は、ローカル開発環境で一般的に使用されるホスト名のセットです。
var localdevHostnames = map[string]struct{}{
	"localhost":            {},
	"127.0.0.1":            {},
	"::1":                  {},
	"host.docker.internal": {},
}

var restrictedIPNetworks = mustParseCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"ff00::/8",
)

// IsSecureServiceURL は、提供されたサービス URL が安全なスキームを使用しているか、ローカル開発ホスト名と一致しているかを確認します。
func IsSecureServiceURL(serviceURL string) bool {
	u, err := url.Parse(serviceURL)
	if err != nil {
		return false
	}

	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return false
	}

	switch scheme {
	case SchemeHTTPS:
		return true
	case SchemeHTTP:
		return isLocalDevHostname(hostname)
	default:
		return false
	}
}

// IsSafeURL は、SSRF (Server-Side Request Forgery) 攻撃を防ぐため、URLの静的検証を行います。
// スキームが許可されているか、ホスト名がプライベートIPに解決されないかを確認します。
// 動的なDNS Rebinding攻撃への対策として、実際のリクエスト発行時にはこの関数と合わせて NewSafeHTTPClient の使用を強く推奨します。
func IsSafeURL(rawURL string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDNSLookupTimeout)
	defer cancel()
	return IsSafeURLContext(ctx, rawURL)
}

// IsSafeURLContext は、context 付きでURLの静的検証を行います。
func IsSafeURLContext(ctx context.Context, rawURL string) (bool, error) {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return false, fmt.Errorf("URLパース失敗: %w", err)
	}

	scheme := strings.ToLower(parsedURL.Scheme)

	switch scheme {
	case SchemeGCS, SchemeS3:
		return true, nil
	case SchemeHTTP, SchemeHTTPS:
		// 検証を続行
	default:
		return false, fmt.Errorf("不許可スキーム: %s", parsedURL.Scheme)
	}

	hostname := strings.ToLower(parsedURL.Hostname())
	if hostname == "" {
		return false, fmt.Errorf("ホストが空です")
	}

	if err := validateHostnameIPs(ctx, hostname); err != nil {
		return false, err
	}

	return true, nil
}

// NewSafeHTTPClient は、接続直前にIP検証を行うことでDNS Rebindingを防ぐクライアントを生成します。
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	// http.DefaultTransport の設定をコピーしてカスタマイズする
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("接続先アドレスの解析に失敗: %w", err)
		}

		// 接続直前に名前解決を行い、解決されたIPを即座にチェックする (TOCTOU対策)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("ホスト '%s' の名前解決結果が空です", host)
		}

		for _, ip := range ips {
			if isRestrictedIP(ip) {
				return nil, fmt.Errorf("restricted IP detected: %s", ip.String())
			}
		}

		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// isLocalDevHostname は、指定されたホスト名が既知のローカル開発ホスト名と一致するかどうかを確認します。
func isLocalDevHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	_, ok := localdevHostnames[hostname]
	return ok
}

// validateHostnameIPs は、指定されたホスト名が制限された IP アドレスに解決されるかどうかを確認します。
func validateHostnameIPs(ctx context.Context, hostname string) error {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return fmt.Errorf("ホスト '%s' の名前解決に失敗: %w", hostname, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("ホスト '%s' の名前解決結果が空です", hostname)
	}

	for _, ip := range ips {
		if isRestrictedIP(ip) {
			return fmt.Errorf("制限されたネットワークへのアクセスを検知: %s", ip.String())
		}
	}
	return nil
}

// isRestrictedIP は、指定されたIPアドレスがプライベート、ループバック、またはリンクローカルアドレスであるかを判定します。
func isRestrictedIP(ip net.IP) bool {
	if ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() {
		return true
	}

	for _, network := range restrictedIPNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid restricted IP network %q: %v", cidr, err))
		}
		networks = append(networks, network)
	}
	return networks
}
