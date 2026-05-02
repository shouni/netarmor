# 🛡️ Net Armor

[![Language](https://img.shields.io/badge/Language-Go-blue)](https://golang.org/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/netarmor)](https://golang.org/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/netarmor)](https://github.com/shouni/netarmor/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)](#)

## 💡 概要 (About)— 鉄壁のネットワーク防御と回復力を提供する高信頼性ユーティリティ

**Net Armor** は、Go言語アプリケーションの外部通信における「安定性」と「安全性」を強化するためのネットワークユーティリティキットです。

一時的なネットワークエラーに対する指数バックオフリトライ機能と、SSRF (Server-Side Request Forgery) や DNS Rebinding 攻撃からインフラを保護するセキュリティ機能を提供します。

## ✨ 特徴

* **堅牢なリトライ (`retry`)**: `backoff/v4` をベースに、Context キャンセルや最大試行回数を直感的に扱えるインターフェースを提供。
* **強力な防御 (`securenet`)**: HTTP クライアントの Transport 層で接続直前に IP アドレスを検証し、検証済み IP に接続します。DNS Rebinding 等の TOCTOU 攻撃を遮断します。
* **クラウド対応**: HTTP/HTTPS だけでなく、`gs://` (GCS) や `s3://` (S3) といったクラウドストレージ用スキームの検証にも対応。
* **モジュール性**: 各パッケージは独立しており、必要な機能のみをインポートして利用可能です。

---

## 📦 パッケージ構成 (Package Structure)

| パッケージ | 説明 | 主な提供機能 |
| --- | --- | --- |
| **`securenet`** | **ネットワークセキュリティ**。SSRF 対策や、サービス URL の妥当性判定を行います。 | 安全な HTTP クライアント (`NewSafeHTTPClient`)、URL 検証 (`IsSafeURL`)、サービス URL 判定 |
| **`retry`** | **耐障害性向上**。一時的なエラーが発生した際に、指数バックオフを用いて再試行します。 | バックオフ付きリトライ実行 (`Do`)、設定補完 (`withDefaults`) |

---

## 🚀 クイックスタート

### 1. 安全な HTTP リクエスト (`securenet`)

DNS Rebinding 攻撃を防ぐため、接続を確立する直前に名前解決を行い、解決された IP アドレスがプライベート範囲でないか検証します。
安全な HTTP クライアントは環境変数の `HTTP_PROXY` / `HTTPS_PROXY` を使用しません。

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

```

URL の静的検証に timeout やキャンセルを適用したい場合は、`IsSafeURLContext` を使用できます。

```go
import (
    "context"
    "time"

    "github.com/shouni/netarmor/securenet"
)

ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

safe, err := securenet.IsSafeURLContext(ctx, "https://api.example.com/data")

```

### 2. 指数バックオフリトライ (`retry`)

一時的な接続エラーに対し、適切な待機時間を挟みながら自動的にリトライを行います。

```go
import (
    "context"
    "github.com/shouni/netarmor/retry"
)

err := retry.Do(
    context.Background(),
    retry.DefaultConfig(),
    "ExternalAPI",
    func() error {
        // リトライしたい処理（APIコールなど）
        return callRemoteResource()
    },
    func(err error) bool {
        // リトライすべきエラーかどうかを判定（例：5xxエラーなど）
        return isTransient(err)
    },
)

```

---

## 🛡️ セキュリティポリシー

`securenet` パッケージは、デフォルトで以下のアクセスを「制限されたネットワーク」として検知し、ブロックします。

* プライベート IP アドレス範囲 (RFC 1918)
* ループバックアドレス (localhost, 127.0.0.1, ::1)
* リンクローカルアドレス (169.254.0.0/16 等)
* 未指定アドレス (0.0.0.0, ::)
* Carrier-grade NAT 範囲 (100.64.0.0/10)
* ベンチマーク用ネットワーク (198.18.0.0/15)
* マルチキャスト、予約済みアドレス範囲

`IsSecureServiceURL` は HTTPS URL またはローカル開発用 HTTP URL を許可しますが、ホスト名が空の URL は拒否します。

---

### 📜 ライセンス (License)

このプロジェクトは [MIT License](https://opensource.org/licenses/MIT) の下で公開されています。
