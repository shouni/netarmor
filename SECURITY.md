# セキュリティポリシー (Security Policy)

## サポート対象バージョン (Supported Versions)

| バージョン | サポート状況 |
| --- | --- |
| v1.2.x | ✅ サポート中 |
| v1.1.x 以前 | ❌ 非サポート |

## 脆弱性の報告 (Reporting a Vulnerability)

**脆弱性を公開の Issue で報告しないでください。**

GitHub の [Private vulnerability reporting](https://github.com/shouni/netarmor/security/advisories/new) から非公開で報告してください。

報告には以下を含めてください。

- 影響を受けるパッケージ (`securenet` / `retry`) とバージョン
- 再現手順、または PoC コード
- 想定される影響（SSRF 迂回、情報漏洩など）

初回応答の目安は 7 日以内です。修正が必要と判断した場合は、パッチ公開後に GitHub Security Advisory として公開します。

## 脅威モデル (Threat Model)

`securenet` は「アプリケーションが外部から与えられた URL を取得する」場面で、内部ネットワークへの到達を防ぐことを目的としています。

### 防御対象

- **SSRF**: プライベート / ループバック / リンクローカル / CGNAT / 予約済みアドレス、および NAT64 / 6to4 / Teredo のような IPv4 を埋め込める変換範囲への接続（既定のブロック対象の一覧は README を参照）
- **DNS Rebinding (TOCTOU)**: 検証後・接続前に DNS 応答が差し替えられる攻撃。`NewSafeHTTPClient` および `NewSafeTransport` は接続直前に名前解決を行い、**検証済みの IP アドレスに対して直接ダイヤル**することで防ぎます
- **IPv4-mapped IPv6 による回避**: `::ffff:127.0.0.1` のような表記は `netip.Addr.Unmap()` で正規化してから判定します
- **プロキシ経由の迂回**: 環境変数 `HTTP_PROXY` / `HTTPS_PROXY` は既定で無効です
- **リダイレクトによるダウングレード**: https から http へのリダイレクトは既定で拒否されます

### 防御対象外 (Out of Scope)

以下は本パッケージの責務ではありません。利用側での対策が必要です。

- **`ValidateURL` 単体での使用**: 静的検証のみでは DNS Rebinding を防げません。必ず `NewSafeHTTPClient` / `NewSafeTransport` と併用してください
- **`WithProxy` 有効時の最終宛先**: 接続先はプロキシサーバになるため、最終的な宛先 IP は検証されません
- **`WithAllowLoopback` / `WithAllowPrivate` / `WithAllowLinkLocal` 有効時**: 明示的にポリシーを緩めた場合の結果は利用側の責任です
- **レスポンスボディのサイズ・内容**: 展開爆弾やレスポンス内容の検証は行いません
- **アプリケーション層の認可**: 到達可能な公開エンドポイントへのアクセス制御

### fail-closed 方針

ホスト名が複数の IP アドレスに解決される場合、そのうち 1 つでも制限対象であれば接続全体を拒否します。「安全な IP だけを選んで接続する」方式は、攻撃者が解決順序を操作できる状況で回避されうるため採用していません。
