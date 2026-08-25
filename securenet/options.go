package securenet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"
)

// Resolver は名前解決の抽象です。*net.Resolver がそのまま満たすため、
// 本番では net.DefaultResolver を、テストではフェイク実装を差し込めます。
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// defaultBlockedPrefixes は、Go 標準の判定メソッド（IsPrivate / IsLoopback 等）では
// カバーされない、追加でブロックすべきネットワークです。
//
//   - 0.0.0.0/8         : "this network" (RFC 1122)
//   - 100.64.0.0/10     : Carrier-grade NAT (RFC 6598)
//   - 192.0.0.0/24      : IETF プロトコル割り当て (RFC 6890)
//   - 192.0.2.0/24      : TEST-NET-1 (RFC 5737)
//   - 192.88.99.0/24    : 6to4 リレーエニーキャスト (廃止, RFC 7526)
//   - 198.18.0.0/15     : ベンチマーク用 (RFC 2544)
//   - 198.51.100.0/24   : TEST-NET-2 (RFC 5737)
//   - 203.0.113.0/24    : TEST-NET-3 (RFC 5737)
//   - 240.0.0.0/4       : 予約済み (RFC 1112)
//   - 64:ff9b::/96      : NAT64 well-known prefix (RFC 6052)
//   - 64:ff9b:1::/48    : IPv4/IPv6 変換・ローカル用 (RFC 8215)
//   - 100::/64          : Discard-Only (RFC 6666)
//   - 2001::/32         : Teredo (RFC 4380)
//   - 2001:db8::/32     : ドキュメント用 (RFC 3849)
//   - 2002::/16         : 6to4 (RFC 3056)
//   - 3fff::/20         : ドキュメント用・拡張 (RFC 9637)
//   - 5f00::/16         : SRv6 SID (RFC 9602)
//   - fec0::/10         : サイトローカル (廃止, RFC 3879)
//
// NAT64 / 6to4 / Teredo の変換範囲は、アドレス内に IPv4 を埋め込めるため、
// 埋め込んだ内部 IPv4（例: 64:ff9b::a9fe:a9fe はメタデータエンドポイント）への
// 到達経路になりえます。埋め込み先を個別に検査する代わりに範囲全体を fail-closed で
// ブロックします。NAT64 環境で正当に必要な場合は WithAllowedCIDRs で明示的に
// 許可してください（その場合、埋め込み IPv4 の検査は行われない点に注意）。
var defaultBlockedPrefixes = mustParsePrefixes(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/32",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
	"5f00::/16",
	"fec0::/10",
)

// policy は、ある IP アドレスへの接続を許可するかどうかを決定します。
type policy struct {
	allowed        []netip.Prefix
	blocked        []netip.Prefix
	allowLoopback  bool
	allowPrivate   bool
	allowLinkLocal bool
}

// isRestricted は、指定されたアドレスが接続を禁止されているかを判定します。
//
// 判定順序は「許可リスト → 標準判定 → ブロックリスト」です。
// 許可リストが最優先されるため、WithAllowedCIDRs で明示的に許可された
// アドレスは他のすべてのルールに優先して接続が許可されます。
func (p *policy) isRestricted(addr netip.Addr) bool {
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) を IPv4 に正規化してから判定する。
	// これを怠ると mapped 形式でプライベート IP 判定を回避されうる。
	a := addr.Unmap()

	if !a.IsValid() {
		return true
	}

	for _, pre := range p.allowed {
		if pre.Contains(a) {
			return false
		}
	}

	switch {
	case a.IsLoopback():
		return !p.allowLoopback
	case a.IsPrivate():
		return !p.allowPrivate
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return !p.allowLinkLocal
	// IsMulticast は IPv6 の ff00::/8 全体を含むため、インターフェースローカル
	// マルチキャスト (ff01::/16) の判定は不要。
	case a.IsUnspecified(), a.IsMulticast():
		return true
	}

	for _, pre := range p.blocked {
		if pre.Contains(a) {
			return true
		}
	}

	return false
}

// options は securenet の各コンストラクタに共通する設定です。
type options struct {
	policy         policy
	resolver       Resolver
	proxy          func(*http.Request) (*url.URL, error)
	baseTransport  *http.Transport
	dialer         *net.Dialer
	maxRedirects   int
	allowDowngrade bool
}

// Option は securenet の挙動を調整します。
type Option func(*options)

// defaultOptions は「何も指定しない場合」の安全側の既定値を返します。
func defaultOptions() options {
	return options{
		policy: policy{
			// Clip で cap == len にしておくことで、WithBlockedCIDRs の append が
			// パッケージ共有のバッキング配列を書き換えることを防ぐ。
			blocked: slices.Clip(defaultBlockedPrefixes),
		},
		resolver:     net.DefaultResolver,
		proxy:        nil, // 環境変数のプロキシは既定で無効
		maxRedirects: 10,
	}
}

func newOptions(opts []Option) *options {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return &o
}

// WithResolver は名前解決に使うリゾルバを差し替えます。
// テストで実 DNS への依存を避けたい場合に使用します。
func WithResolver(r Resolver) Option {
	return func(o *options) {
		if r != nil {
			o.resolver = r
		}
	}
}

// WithProxy は HTTP プロキシの選択関数を設定します。
//
// 既定ではプロキシは無効です。これは HTTP_PROXY / HTTPS_PROXY を悪用して
// IP 検証を迂回されることを防ぐためですが、社内プロキシ経由が必須の環境では
// このオプションで明示的に有効化できます。
//
// プロキシを使用する場合、DialContext が受け取る接続先はプロキシサーバの
// アドレスになります。したがって次の 2 点に注意してください。
//
//   - 最終的な宛先 IP に対する検証は効きません。プロキシ自身が信頼できることが前提です。
//   - プロキシがプライベートアドレスに存在する場合、既定のポリシーではその接続自体が
//     拒否されます。WithAllowedCIDRs でプロキシのアドレスを明示的に許可してください。
func WithProxy(fn func(*http.Request) (*url.URL, error)) Option {
	return func(o *options) { o.proxy = fn }
}

// WithProxyFromEnvironment は HTTP_PROXY / HTTPS_PROXY / NO_PROXY を有効化します。
// トレードオフについては WithProxy のドキュメントを参照してください。
func WithProxyFromEnvironment() Option {
	return WithProxy(http.ProxyFromEnvironment)
}

// WithAllowedCIDRs は、既定のポリシーで拒否されるアドレスであっても
// 接続を許可するネットワークを追加します。許可リストは他のすべての判定に優先します。
//
// 不正な CIDR 表記は無視されます。事前に検証したい場合は netip.ParsePrefix を使用してください。
func WithAllowedCIDRs(cidrs ...string) Option {
	return func(o *options) {
		for _, c := range cidrs {
			if pre, err := netip.ParsePrefix(c); err == nil {
				o.policy.allowed = append(o.policy.allowed, pre.Masked())
			}
		}
	}
}

// WithAllowedPrefixes は WithAllowedCIDRs のパース済み版です。
func WithAllowedPrefixes(prefixes ...netip.Prefix) Option {
	return func(o *options) {
		for _, pre := range prefixes {
			o.policy.allowed = append(o.policy.allowed, pre.Masked())
		}
	}
}

// WithBlockedCIDRs は、既定のブロック一覧に追加でネットワークを登録します。
//
// 不正な CIDR 表記は無視されます。事前に検証したい場合は netip.ParsePrefix を使用してください。
func WithBlockedCIDRs(cidrs ...string) Option {
	return func(o *options) {
		for _, c := range cidrs {
			if pre, err := netip.ParsePrefix(c); err == nil {
				o.policy.blocked = append(o.policy.blocked, pre.Masked())
			}
		}
	}
}

// WithAllowLoopback はループバックアドレスへの接続を許可します。
// テストで httptest.NewServer を対象にする場合などに使用します。
// 本番環境で有効にすると SSRF 防御が大きく損なわれます。
func WithAllowLoopback() Option {
	return func(o *options) { o.policy.allowLoopback = true }
}

// WithAllowPrivate は RFC 1918 のプライベートアドレスへの接続を許可します。
// 本番環境で有効にすると SSRF 防御が大きく損なわれます。
func WithAllowPrivate() Option {
	return func(o *options) { o.policy.allowPrivate = true }
}

// WithAllowLinkLocal はリンクローカルアドレスへの接続を許可します。
// 169.254.169.254 などのクラウドメタデータエンドポイントが到達可能になるため、
// 有効化は極力避けてください。
func WithAllowLinkLocal() Option {
	return func(o *options) { o.policy.allowLinkLocal = true }
}

// WithBaseTransport は、複製元となる *http.Transport を指定します。
// HTTP/2 設定やコネクションプールの調整を持ち込みたい場合に使用します。
//
// 指定した Transport は複製された上で、次のフィールドが securenet に上書きされます。
//
//   - Proxy / DialContext : 検証付きの実装に差し替えられます。
//   - DialTLSContext / DialTLS / Dial : nil にされます。DialTLSContext が
//     設定されていると HTTPS で DialContext が呼ばれず IP 検証が迂回されるため、
//     本パッケージでは無効化します。TLS の設定は TLSClientConfig で行ってください。
func WithBaseTransport(t *http.Transport) Option {
	return func(o *options) { o.baseTransport = t }
}

// WithDialer は接続に使用する *net.Dialer を差し替えます。
// Dialer の Control フックなどを利用したい場合に使用します。
// 指定した場合、コンストラクタに渡した timeout は Dialer には適用されないため、
// 必要なら Dialer 側の Timeout を自分で設定してください。
func WithDialer(d *net.Dialer) Option {
	return func(o *options) { o.dialer = d }
}

// WithMaxRedirects は追従するリダイレクトの最大回数を設定します。
// 0 を指定するとリダイレクトを一切追従しません。負値は既定値 (10) として扱われます。
func WithMaxRedirects(n int) Option {
	return func(o *options) {
		if n >= 0 {
			o.maxRedirects = n
		}
	}
}

// WithAllowRedirectDowngrade は https から http へのリダイレクト追従を許可します。
// 既定ではダウングレードを伴うリダイレクトは拒否されます。
func WithAllowRedirectDowngrade() Option {
	return func(o *options) { o.allowDowngrade = true }
}

func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		pre, err := netip.ParsePrefix(c)
		if err != nil {
			panic(fmt.Sprintf("securenet: invalid blocked prefix %q: %v", c, err))
		}
		prefixes = append(prefixes, pre.Masked())
	}
	return prefixes
}

// newDialer は options から接続用の Dialer を生成します。
func (o *options) newDialer(timeout time.Duration) *net.Dialer {
	if o.dialer != nil {
		return o.dialer
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
}
