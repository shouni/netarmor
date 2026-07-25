// Package retry は、指数バックオフとカスタムエラー判定を用いて
// 操作をリトライするためのユーティリティを提供します。
//
// # 基本的な使い方
//
//	err := retry.Run(ctx, func() error { return callAPI() },
//	    retry.WithName("ExternalAPI"),
//	    retry.WithMaxRetries(5),
//	    retry.WithShouldRetry(isTransient),
//	    retry.WithNotify(func(err error, attempt uint, next time.Duration) {
//	        slog.Warn("retrying", "attempt", attempt, "next", next, "err", err)
//	    }),
//	)
//
// 戻り値を伴う操作には RunValue を使用します。
//
//	body, err := retry.RunValue(ctx, func() ([]byte, error) { return fetch(ctx) },
//	    retry.WithMaxRetries(3),
//	)
//
// # 打ち切り条件
//
// リトライは「最大試行回数」と「コンテキストの終了」で打ち切られます。
// 経過時間による打ち切りは既定で無効です（WithMaxElapsedTime で有効化できます）。
//
// # エラー
//
// 失敗時に返るのは *Error で、errors.Is により ErrExhausted / ErrPermanent /
// コンテキストのエラー / 操作自身が返した最後のエラーのいずれとも比較できます。
//
//	if errors.Is(err, retry.ErrExhausted) { ... }
//	if errors.Is(err, context.DeadlineExceeded) { ... }
package retry

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v5"
)

// Run は指数バックオフを使用して操作をリトライします。
// 成功した場合は nil を、失敗した場合は *Error を返します。
//
// ctx が nil の場合は context.Background() として扱われます。
func Run(ctx context.Context, op Operation, opts ...Option) error {
	if op == nil {
		return ErrNilOperation
	}
	_, err := RunValue(ctx, func() (struct{}, error) {
		return struct{}{}, op()
	}, opts...)
	return err
}

// RunValue は Run の戻り値つき版です。操作が返した値をそのまま返します。
// 失敗した場合、値は最後の試行が返したもの（多くの場合ゼロ値）になります。
//
// ctx が nil の場合は context.Background() として扱われます。
func RunValue[T any](ctx context.Context, op func() (T, error), opts ...Option) (T, error) {
	var zero T
	if op == nil {
		return zero, ErrNilOperation
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s := newSettings(opts)

	var (
		attempts  uint
		lastErr   error
		permanent bool
	)

	wrapped := func() (T, error) {
		attempts++
		v, err := op()
		if err == nil {
			return v, nil
		}
		lastErr = err

		// リトライ不要と判定された場合は backoff にそれ以上試行させない。
		if s.shouldRetry != nil && !s.shouldRetry(err) {
			permanent = true
			return v, backoff.Permanent(err)
		}
		return v, err
	}

	boOpts := []backoff.RetryOption{
		backoff.WithBackOff(&backoff.ExponentialBackOff{
			InitialInterval:     s.initialInterval,
			MaxInterval:         s.maxInterval,
			Multiplier:          s.multiplier,
			RandomizationFactor: s.randomizationFactor,
		}),
		// backoff の MaxTries は初回実行を含む総試行回数。
		backoff.WithMaxTries(addSaturating(s.maxRetries, 1)),
		backoff.WithMaxElapsedTime(s.maxElapsedTime),
	}
	if s.notify != nil {
		boOpts = append(boOpts, backoff.WithNotify(func(err error, next time.Duration) {
			s.notify(err, attempts, next)
		}))
	}

	v, err := backoff.Retry(ctx, wrapped, boOpts...)
	if err == nil {
		return v, nil
	}

	// backoff はコンテキスト終了時に操作エラーを捨てて context.Cause だけを返すため、
	// 呼び出し側が原因を追えるよう lastErr と両方を保持する。
	return v, &Error{
		Op:        s.name,
		Attempts:  attempts,
		Permanent: permanent,
		Err:       lastErr,
		Cause:     context.Cause(ctx),
	}
}

// addSaturating は uint のオーバーフローを飽和させて加算します。
func addSaturating(a, b uint) uint {
	if a > ^uint(0)-b {
		return ^uint(0)
	}
	return a + b
}
