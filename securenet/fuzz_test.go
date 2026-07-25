package securenet_test

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/shouni/netarmor/securenet"
)

// fuzzResolver は fuzz 中に実 DNS を引かないための固定リゾルバです。
// 既知のホストだけ公開 IP を返し、それ以外は解決失敗させます。
type fuzzResolver struct{}

func (fuzzResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == "public.test" {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	return nil, &url.Error{Op: "lookup", URL: host, Err: context.DeadlineExceeded}
}

// FuzzValidateURL は URL パース経路が panic せず、
// かつ「成功したなら必ず許可スキーム・非空ホストである」という不変条件を満たすことを検証します。
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

		// 成功した場合、必ずパース可能で許可スキームでなければならない。
		u, parseErr := url.ParseRequestURI(raw)
		if parseErr != nil {
			t.Fatalf("ValidateURL は成功したがパースできません: %q", raw)
		}

		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case securenet.SchemeGCS, securenet.SchemeS3:
			// クラウドストレージは名前解決なしで許可される
		case securenet.SchemeHTTP, securenet.SchemeHTTPS:
			if u.Hostname() == "" {
				t.Fatalf("ホストが空なのに成功しました: %q", raw)
			}
		default:
			t.Fatalf("許可されないスキーム %q で成功しました: %q", scheme, raw)
		}
	})
}

// FuzzIsSecureServiceURL は、true を返す入力が必ず
// パース可能かつ http/https スキームであることを検証します。
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
			t.Fatalf("true を返したがパースできません: %q", raw)
		}
		if u.Hostname() == "" {
			t.Fatalf("true を返したがホストが空です: %q", raw)
		}

		scheme := strings.ToLower(u.Scheme)
		if scheme != securenet.SchemeHTTP && scheme != securenet.SchemeHTTPS {
			t.Fatalf("true を返したがスキームが %q です: %q", scheme, raw)
		}
		if scheme == securenet.SchemeHTTP && !securenet.IsSecureServiceURL("https://"+u.Host) {
			t.Fatalf("http を許可したがローカル開発ホストではありません: %q", raw)
		}
	})
}
