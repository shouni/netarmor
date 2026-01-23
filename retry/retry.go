package retry

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
)

const (
	DefaultMaxRetries      = 3
	InitialBackoffInterval = 5 * time.Second
	MaxBackoffInterval     = 30 * time.Second
)

// Operation はリトライ可能な処理を表す関数です。
type Operation func() error

// ShouldRetryFunc はエラーを受け取り、そのエラーがリトライ可能かどうかを判定します。
type ShouldRetryFunc func(error) bool

// Config はリトライ動作を設定するための構造体です。
type Config struct {
	MaxRetries      uint64
	InitialInterval time.Duration
	MaxInterval     time.Duration
}

// DefaultConfig は推奨されるデフォルト設定を返します。
func DefaultConfig() Config {
	return Config{
		MaxRetries:      DefaultMaxRetries,
		InitialInterval: InitialBackoffInterval,
		MaxInterval:     MaxBackoffInterval,
	}
}

// withDefaults は未設定(0値)の項目をデフォルトで補完します。
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.InitialInterval == 0 {
		c.InitialInterval = d.InitialInterval
	}
	if c.MaxInterval == 0 {
		c.MaxInterval = d.MaxInterval
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = d.MaxRetries
	}
	return c
}

// newBackOffPolicy は設定とコンテキストから backoff.BackOff を生成します。
func newBackOffPolicy(ctx context.Context, cfg Config) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = cfg.InitialInterval
	b.MaxInterval = cfg.MaxInterval
	// 回数ベースのリトライを優先するため、経過時間による打ち切り(デフォルト15分)を無効化
	b.MaxElapsedTime = 0

	// 最大リトライ回数を制限
	bo := backoff.WithMaxRetries(b, cfg.MaxRetries)
	// コンテキストによるキャンセル・タイムアウトを監視
	return backoff.WithContext(bo, ctx)
}

// Do は指数バックオフとカスタムエラー判定を使用して操作をリトライします。
func Do(ctx context.Context, cfg Config, operationName string, op Operation, shouldRetryFn ShouldRetryFunc) error {
	cfg = cfg.withDefaults()
	bo := newBackOffPolicy(ctx, cfg)

	var isPermanent bool // 永続的エラー（リトライ不要）が発生したかどうかのフラグ

	retryableOp := func() error {
		err := op()
		if err == nil {
			return nil
		}

		// リトライ不要判定
		if shouldRetryFn != nil && !shouldRetryFn(err) {
			isPermanent = true
			return backoff.Permanent(err)
		}
		return err
	}

	err := backoff.Retry(retryableOp, bo)
	if err == nil {
		return nil
	}

	// 1. 永続的エラー（ShouldRetryFunc が false を返した）の場合
	if isPermanent {
		return fmt.Errorf("%sに失敗しました: 致命的なエラーのため中止: %w", operationName, err)
	}

	// 2. コンテキストによる中断（タイムアウト・キャンセル）の場合
	if ctx.Err() != nil {
		return fmt.Errorf("%sに失敗しました: コンテキストが終了しました: %w", operationName, ctx.Err())
	}

	// 3. 最大リトライ回数到達
	return fmt.Errorf("%sに失敗しました: 最大リトライ回数 (%d回) 到達。最終エラー: %w", operationName, cfg.MaxRetries, err)
}
