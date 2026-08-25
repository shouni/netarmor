// Package securenet は、SSRF (Server-Side Request Forgery) 対策として、
// URL のスキーム検証や DNS Rebinding 対策済みの HTTP クライアント生成を行うユーティリティを提供します。
//
// # 二段構えの防御
//
// 本パッケージは目的の異なる 2 つの検証層を提供します。両方を併用してください。
//
//  1. 静的検証 (ValidateURL): リクエストを発行する前に URL を弾くための事前チェックです。
//     ユーザー入力を受け付けた時点で早期にエラーを返す用途に向いています。
//  2. 接続時検証 (NewSafeHTTPClient / NewSafeTransport): DNS Rebinding のような
//     TOCTOU 攻撃に対する本体の防御です。接続を確立する直前に名前解決を行い、
//     検証済みの IP アドレスに対して直接ダイヤルします。
//
// 静的検証だけでは、検証後・接続前に DNS 応答が差し替えられる攻撃を防げません。
// 権威ある防御は常に接続時検証の側にあります。
//
// # fail-closed 方針
//
// ホスト名が複数の IP アドレスに解決される場合、そのうち 1 つでも制限対象で
// あれば接続全体を拒否します。「安全な IP だけを選んで接続する」方式は、
// 攻撃者が解決順序を操作できる状況で回避されうるため採用していません。
//
// # プロキシ
//
// 生成されるクライアントは既定で HTTP_PROXY / HTTPS_PROXY を使用しません。
// 環境変数経由で IP 検証を迂回されることを防ぐためです。
// 明示的に有効化するには WithProxy または WithProxyFromEnvironment を使用してください。
package securenet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// SchemeHTTP は平文 HTTP スキームを表します。
	// IsSecureServiceURL ではローカル開発ホスト名との組み合わせでのみ許可されます
	// （ValidateURL と接続時検証では制限対象でないホストへの http は許可されます）。
	SchemeHTTP = "http"
	// SchemeHTTPS は暗号化された HTTPS スキームを表します。
	SchemeHTTPS = "https"
)

// localdevHostnames は、ローカル開発環境で一般的に使用されるホスト名のセットです。
var localdevHostnames = map[string]struct{}{
	"localhost":            {},
	"127.0.0.1":            {},
	"::1":                  {},
	"host.docker.internal": {},
}

// IsSecureServiceURL は、提供されたサービス URL が安全なスキームを使用しているか、
// ローカル開発ホスト名と一致しているかを確認します。
//
// これは設定値の妥当性を判定するための軽量なチェックであり、名前解決を行いません。
// 「その URL を実際に取得して安全か」を判定するものではないため、
// 外部から与えられた URL を検証する用途には ValidateURL を使用してください。
func IsSecureServiceURL(serviceURL string) bool {
	u, err := url.ParseRequestURI(serviceURL)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return false
	}

	switch strings.ToLower(u.Scheme) {
	case SchemeHTTPS:
		return true
	case SchemeHTTP:
		return isLocalDevHostname(hostname)
	default:
		return false
	}
}

// ValidateURL は、SSRF 攻撃を防ぐために URL の静的検証を行います。
// 安全と判断された場合は nil を、そうでない場合は失敗理由を表すエラーを返します。
//
// 返されるエラーは errors.Is / errors.As で分類できます。
//
//	err := securenet.ValidateURL(ctx, rawURL)
//	switch {
//	case errors.Is(err, securenet.ErrRestrictedIP):
//		// 制限されたネットワークへのアクセス
//	case errors.Is(err, securenet.ErrDisallowedScheme):
//		// 許可されていないスキーム
//	}
//
// 許可されるスキームは http と https だけです。それ以外はすべて
// ErrDisallowedScheme になります。
//
// 名前解決のタイムアウトは ctx で制御してください。本関数は独自のタイムアウトを設定しません。
func ValidateURL(ctx context.Context, rawURL string, opts ...Option) error {
	return newOptions(opts).validateURL(ctx, rawURL)
}

// NewSafeTransport は、接続直前に IP 検証を行う *http.Transport を生成します。
//
// 独自の *http.Client（cookiejar や計装付き）を構築したい場合に使用してください。
// 単に安全なクライアントが欲しい場合は NewSafeHTTPClient を使用します。
//
// リダイレクトポリシー (WithMaxRedirects / WithAllowRedirectDowngrade) は
// *http.Client.CheckRedirect 側の機能のため、返される Transport には含まれません。
// 自前で *http.Client を組むとこれらのオプションは無視され、Go 既定の挙動
// （10 回まで追従し、https から http へのダウングレードも制限しない）になります。
// リダイレクトの制御が必要な場合は NewSafeHTTPClient を使用してください。
func NewSafeTransport(timeout time.Duration, opts ...Option) *http.Transport {
	return newOptions(opts).newTransport(timeout)
}

// NewSafeHTTPClient は、接続直前に IP 検証を行うことで DNS Rebinding を防ぐクライアントを生成します。
//
// 既定では以下のポリシーが適用されます。
//   - プライベート / ループバック / リンクローカル等への接続を拒否
//   - 環境変数によるプロキシを無効化
//   - リダイレクト追従は最大 10 回、https から http へのダウングレードは拒否
//
// これらは Option で調整できます。
func NewSafeHTTPClient(timeout time.Duration, opts ...Option) *http.Client {
	o := newOptions(opts)
	return &http.Client{
		Transport:     o.newTransport(timeout),
		Timeout:       timeout,
		CheckRedirect: o.checkRedirect,
	}
}

// newTransport は options から検証付き Transport を生成します。
func (o *options) newTransport(timeout time.Duration) *http.Transport {
	transport := o.cloneBaseTransport()
	transport.Proxy = o.proxy
	transport.DialContext = o.dialContext(o.newDialer(timeout))

	// DialTLSContext が設定されていると、HTTPS では DialContext が呼ばれず
	// IP 検証が丸ごと迂回される（net/http の仕様）。安全側に倒して無効化する。
	//
	// 非推奨の DialTLS / Dial も落とす。DialTLS は DialTLSContext が nil のときの
	// フォールバックとして net/http の customDialTLS で現役のため、消さないと穴が残る。
	// Dial は DialContext を必ず設定するので到達しないが、多層防御として揃えておく。
	transport.DialTLSContext = nil
	transport.DialTLS = nil //nolint:staticcheck // 使うためではなく、検証を迂回されないよう無効化するための代入
	transport.Dial = nil    //nolint:staticcheck // 同上

	return transport
}

// cloneBaseTransport は複製元の Transport を決定して複製します。
func (o *options) cloneBaseTransport() *http.Transport {
	if o.baseTransport != nil {
		return o.baseTransport.Clone()
	}
	// http.DefaultTransport は計装ライブラリ等にグローバルで差し替えられている
	// ことがある。型アサーションで panic しないよう、*http.Transport でなければ
	// 標準と同等の既定値から組み立てる。
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		return dt.Clone()
	}
	return &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// dialContext は、接続直前に名前解決と IP 検証を行うダイヤル関数を返します。
func (o *options) dialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// net.Dialer.Timeout は DialContext 1 回ごとに適用されるため、解決した
		// アドレスごとに呼ぶと合計で「アドレス数 × timeout」まで伸びうる。
		// 標準の net.Dialer と同じく、名前解決を含む 1 回のダイヤル全体を上限とする。
		if dialer.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dialer.Timeout)
			defer cancel()
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("securenet: split host port %q: %w", addr, err)
		}

		// 接続直前に名前解決を行い、解決された IP を即座に検証する (TOCTOU 対策)
		addrs, err := o.resolveAndCheck(ctx, host)
		if err != nil {
			return nil, err
		}

		// 検証済みの IP に対して直接ダイヤルする。ホスト名で再ダイヤルすると
		// ここで再度名前解決が走り、検証を回避されうる。
		var lastErr error
		for _, a := range addrs {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}

// checkRedirect はリダイレクト追従の可否を判定します。
// 返すエラーは errors.Is で ErrTooManyRedirects / ErrRedirectDowngrade と比較できます。
func (o *options) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > o.maxRedirects {
		return &TooManyRedirectsError{Max: o.maxRedirects}
	}
	if !o.allowDowngrade && len(via) > 0 {
		prev := via[len(via)-1]
		if prev.URL.Scheme == SchemeHTTPS && req.URL.Scheme == SchemeHTTP {
			return &RedirectDowngradeError{URL: req.URL.Redacted()}
		}
	}
	return nil
}

// validateURL は URL のスキームとホスト名を検証します。
func (o *options) validateURL(ctx context.Context, rawURL string) error {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return &URLError{URL: rawURL, Err: err}
	}

	switch strings.ToLower(parsed.Scheme) {
	case SchemeHTTP, SchemeHTTPS:
		// 検証を続行
	default:
		return &SchemeError{Scheme: strings.ToLower(parsed.Scheme)}
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return fmt.Errorf("%w: %q", ErrEmptyHost, rawURL)
	}

	_, err = o.resolveAndCheck(ctx, hostname)
	return err
}

// resolveAndCheck はホスト名を解決し、すべての結果がポリシー上許可されることを確認します。
// 1 つでも制限対象が含まれる場合は fail-closed でエラーを返します。
func (o *options) resolveAndCheck(ctx context.Context, host string) ([]netip.Addr, error) {
	// IP リテラルはリゾルバを介さずに直接検証する。
	if a, err := netip.ParseAddr(host); err == nil {
		if o.policy.isRestricted(a) {
			return nil, &BlockedIPError{Host: host, Addr: a}
		}
		return []netip.Addr{a}, nil
	}

	addrs, err := o.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, &ResolveError{Host: host, Err: err}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoAddresses, host)
	}

	for _, a := range addrs {
		if o.policy.isRestricted(a) {
			return nil, &BlockedIPError{Host: host, Addr: a}
		}
	}
	return addrs, nil
}

// isLocalDevHostname は、指定されたホスト名が既知のローカル開発ホスト名と一致するかどうかを確認します。
func isLocalDevHostname(hostname string) bool {
	_, ok := localdevHostnames[hostname]
	return ok
}
