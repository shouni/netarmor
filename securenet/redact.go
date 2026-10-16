package securenet

import (
	"net/url"
	"strings"
)

// redactedQuery は、伏せたクエリの代わりに置く値です。クエリが付いていたことだけを残します。
const redactedQuery = "REDACTED"

// redactedUserinfo は、解析できない URL のユーザー情報の代わりに置く値です。
// url.URL.Redacted がパスワードに使う表記に揃えています。
const redactedUserinfo = "xxxxx"

// redactURL は、エラーに載せる URL の文字列を返します。
//
// エラーはそのままログに出ます。クエリには署名付き URL の署名や `?key=` の API キーが
// 乗ることがあり、url.URL.Redacted が伏せるのはユーザー情報のパスワードだけです。
// そこでクエリとフラグメントは値を落とし、付いていたことだけを残します。
// どこへの接続を拒否したかを追うには、スキーム・ホスト・パスで足ります。
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	if c.RawQuery != "" || c.ForceQuery {
		c.RawQuery = redactedQuery
		c.ForceQuery = false
	}
	c.Fragment, c.RawFragment = "", ""
	return c.Redacted()
}

// redactURLString は redactURL の文字列版です。
//
// 解析できない入力は URLError に載るので、ここが主な使い道です。その場合も、
// `?` / `#` 以降は秘密を含みうるので切り落とし、`://` の後ろのオーソリティに `@` が
// あればユーザー情報ごと伏せます（パスワードだけを見分ける手がかりがないため）。
func redactURLString(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return redactURL(u)
	}

	s := raw
	suffix := ""
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
		suffix = "?" + redactedQuery
	}
	if i := strings.Index(s, "://"); i >= 0 {
		authStart := i + len("://")
		authEnd := len(s)
		if j := strings.IndexByte(s[authStart:], '/'); j >= 0 {
			authEnd = authStart + j
		}
		if at := strings.LastIndexByte(s[authStart:authEnd], '@'); at >= 0 {
			s = s[:authStart] + redactedUserinfo + s[authStart+at:]
		}
	}
	return s + suffix
}

// redactParseError は、url パッケージの解析エラーから入力文字列を伏せた写しを返します。
//
// url.Parse / url.ParseRequestURI の失敗は *url.Error で、入力をそのまま抱えています。
// URLError の URL を伏せても、元のエラーの文面にそのまま出てしまいます。写しを作って
// 差し替えるので、errors.As で *url.Error を取り出す使い方は変わりません。
func redactParseError(err error) error {
	ue, ok := err.(*url.Error)
	if !ok || ue == nil {
		return err
	}
	c := *ue
	c.URL = redactURLString(ue.URL)
	return &c
}
