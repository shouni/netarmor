# 🛡️ Net Armor

[![CI](https://github.com/shouni/netarmor/actions/workflows/ci.yml/badge.svg)](https://github.com/shouni/netarmor/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)
[![Language](https://img.shields.io/badge/Language-Go-blue)](https://golang.org/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/netarmor)](https://golang.org/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/netarmor)](https://github.com/shouni/netarmor/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shouni/netarmor.svg)](https://pkg.go.dev/github.com/shouni/netarmor)

## 💡 概要 (About)

**Net Armor** は、Go アプリケーションの外部通信を SSRF (Server-Side Request Forgery) や DNS Rebinding 攻撃から保護するセキュリティライブラリです。**外部依存を持ちません**（`go.mod` の require は空です）。

> **v1.4.0 で `retry` パッケージを [go-http-kit](https://github.com/shouni/go-http-kit) へ移しました。** 利用者は import パスを `github.com/shouni/go-http-kit/retry` に変更してください。API は変わっていません。

## ✨ 特徴

* **強力な防御 (`securenet`)**: HTTP クライアントの Transport 層で接続直前に IP アドレスを検証し、**検証済み IP に対して直接接続**します。DNS Rebinding 等の TOCTOU 攻撃を遮断します。
* **型付きエラー**: すべての失敗理由を `errors.Is` / `errors.As` で分類できます。エラーメッセージの文字列比較は不要です。
* **テスト容易性**: リゾルバを差し替えられるため、実 DNS に依存しないユニットテストが書けます。
* **依存ゼロ**: 標準ライブラリのみで動きます。取り込んでも利用側のモジュールグラフが広がりません。

---

## 📦 パッケージ構成 (Package Structure)

| パッケージ | 説明 | 主な提供機能 |
| --- | --- | --- |
| **`securenet`** | **ネットワークセキュリティ**。SSRF 対策や、サービス URL の妥当性判定を行います。 | `NewSafeHTTPClient` / `NewSafeTransport` / `ValidateURL` / `IsSecureServiceURL` |

---

## 🚀 クイックスタート

### 1. 安全な HTTP リクエスト (`securenet`)

既定のポリシーは、プライベート / ループバック / リンクローカル等への接続を拒否し、環境変数の `HTTP_PROXY` / `HTTPS_PROXY` を無視します。

```go
import (
    "time"
    "github.com/shouni/netarmor/securenet"
)

// 接続直前のIP検証機能を持つ安全なクライアントを生成
client := securenet.NewSafeHTTPClient(10 * time.Second)

// 安全なURL（例：パブリックなAPI）へのアクセス
resp, err := client.Get("https://api.example.com/data")

// 安全ではないURL（例：内部ネットワークへの攻撃試行）は、DialContext層で遮断されます
_, err = client.Get("http://169.254.169.254/latest/meta-data/")
// errors.Is(err, securenet.ErrRestrictedIP) == true
```

独自の `*http.Client` を組み立てたい場合は Transport だけを取得できます。

```go
client := &http.Client{
    Transport: securenet.NewSafeTransport(10 * time.Second),
    Jar:       jar,
}
```

> ⚠️ **Transport だけを使う場合、リダイレクトポリシーは効きません**（IP 検証は Transport 側なので有効なままです）。理由と影響は [SECURITY.md の防御対象外](SECURITY.md#防御対象外-out-of-scope) を参照してください。

### 2. URL の静的検証

ユーザー入力を受け付けた時点で早期に弾きたい場合は `ValidateURL` を使用します。

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

if err := securenet.ValidateURL(ctx, rawURL); err != nil {
    switch {
    case errors.Is(err, securenet.ErrRestrictedIP):
        // 制限されたネットワークへのアクセス
    case errors.Is(err, securenet.ErrDisallowedScheme):
        // 許可されていないスキーム
    case errors.Is(err, securenet.ErrInvalidURL):
        // URL のパース失敗
    case errors.Is(err, securenet.ErrEmptyHost):
        // ホスト名が空
    case errors.Is(err, securenet.ErrNoAddresses):
        // 名前解決の結果が空
    }
}
```

> ⚠️ **静的検証だけでは DNS Rebinding を防げません。** 検証後・接続前に DNS 応答が差し替えられる攻撃に対する本体の防御は `NewSafeHTTPClient` / `NewSafeTransport` の側にあります。必ず併用してください。

### 3. ポリシーの調整

既定のポリシーは Option で緩めたり厳しくしたりできます。

```go
// テストでローカルサーバに接続する
client := securenet.NewSafeHTTPClient(2*time.Second, securenet.WithAllowLoopback())

// 社内ネットワークの特定範囲だけを許可する
client := securenet.NewSafeHTTPClient(10*time.Second,
    securenet.WithAllowedCIDRs("10.1.0.0/16"))

// 社内プロキシ経由にする（プロキシ自身のアドレスの許可も必要）
client := securenet.NewSafeHTTPClient(10*time.Second,
    securenet.WithProxyFromEnvironment(),
    securenet.WithAllowedCIDRs("10.0.0.0/8"))

// リゾルバを差し替えて実 DNS に依存しないテストを書く
client := securenet.NewSafeHTTPClient(2*time.Second,
    securenet.WithResolver(myFakeResolver))
```

| Option | 用途 |
| --- | --- |
| `WithResolver` | 名前解決の差し替え（テスト用） |
| `WithProxy` / `WithProxyFromEnvironment` | プロキシの明示的な有効化 |
| `WithAllowedCIDRs` / `WithAllowedPrefixes` | 特定ネットワークの許可（最優先） |
| `WithBlockedCIDRs` | 追加のブロック範囲 |
| `WithAllowLoopback` / `WithAllowPrivate` / `WithAllowLinkLocal` | ポリシーの緩和 |
| `WithBaseTransport` / `WithDialer` | Transport / Dialer の持ち込み |
| `WithMaxRedirects` / `WithAllowRedirectDowngrade` | リダイレクトポリシー |

リダイレクトで失敗した場合も型で判別できます。`http.Client` が返す `*url.Error` の包みは `errors.Is` / `errors.As` が透過します。

```go
switch {
case errors.Is(err, securenet.ErrTooManyRedirects):  // 追従回数の上限に到達
case errors.Is(err, securenet.ErrRedirectDowngrade): // https から http へのダウングレード
}
```

---

## 🛡️ セキュリティポリシー

`securenet` パッケージは、デフォルトで以下のアクセスを「制限されたネットワーク」として検知し、ブロックします。

* プライベート IP アドレス範囲 (RFC 1918、IPv6 ULA を含む)
* ループバックアドレス (localhost, 127.0.0.1, ::1)
* リンクローカルアドレス (169.254.0.0/16 等)
* 未指定アドレス (0.0.0.0, ::) と "this network" (0.0.0.0/8)
* Carrier-grade NAT 範囲 (100.64.0.0/10)
* IETF プロトコル割り当て (192.0.0.0/24)、Discard-Only (100::/64)
* ベンチマーク用ネットワーク (198.18.0.0/15)
* ドキュメント用 / TEST-NET 範囲 (192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、2001:db8::/32、3fff::/20)
* IPv4 を埋め込める変換範囲 — NAT64 (64:ff9b::/96、64:ff9b:1::/48)、6to4 (2002::/16、192.88.99.0/24)、Teredo (2001::/32)
* 廃止されたサイトローカル (fec0::/10)、SRv6 SID (5f00::/16)
* マルチキャスト、予約済み範囲 (240.0.0.0/4)

`::ffff:127.0.0.1` のような IPv4-mapped IPv6 表記は正規化した上で判定するため、表記による回避はできません。NAT64 などの変換範囲は、アドレス内に埋め込んだ内部 IPv4（例: `64:ff9b::a9fe:a9fe` はメタデータエンドポイント）への到達経路になりうるため範囲全体をブロックします。NAT64 環境で正当に必要な場合は `WithAllowedCIDRs` で明示的に許可してください。

ホスト名が複数の IP に解決される場合、**1 つでも制限対象があれば全体を拒否します** (fail-closed)。

`IsSecureServiceURL` は HTTPS URL またはローカル開発用 HTTP URL を許可しますが、ホスト名が空の URL は拒否します。これは設定値の妥当性チェックであり、名前解決を行いません。

脅威モデルの詳細と脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

---

## 📜 ライセンス (License)

このプロジェクトは [MIT License](https://opensource.org/licenses/MIT) の下で公開されています。
