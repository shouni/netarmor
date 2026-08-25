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
// 操作にコンテキストを渡したい場合は RunCtx / RunValueCtx を使用します。
//
//	err := retry.RunCtx(ctx, func(ctx context.Context) error { return callAPI(ctx) })
//
// # 打ち切り条件
//
// リトライは「最大試行回数」と「コンテキストの終了」で打ち切られます。
// 経過時間による打ち切りは既定で無効です（WithMaxElapsedTime で有効化できます）。
//
// # 待機時間のヒント
//
// 操作が返すエラーが DelayHinter を実装している場合、次の待機時間は
// 指数バックオフの算出値ではなくその指示値になります（HTTP の Retry-After 対応など）。
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
	"errors"
	"time"

	"github.com/cenkalti/backoff/v7"
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

// RunCtx は Run の、操作がコンテキストを受け取る版です。
// 操作には呼び出し側が渡した ctx がそのまま渡されるため、クロージャで
// ctx を捕捉する必要がありません。
//
//	err := retry.RunCtx(ctx, func(ctx context.Context) error {
//	    return callAPI(ctx)
//	}, retry.WithMaxRetries(5))
//
// ctx はリトライループを打ち切りますが、実行中の操作を中断するのは
// 操作自身が ctx を監視している場合だけです。
//
// ctx が nil の場合は context.Background() として扱われ、操作にもそれが渡されます。
func RunCtx(ctx context.Context, op OperationCtx, opts ...Option) error {
	if op == nil {
		return ErrNilOperation
	}
	_, err := RunValueCtx(ctx, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, op(ctx)
	}, opts...)
	return err
}

// RunValueCtx は RunValue の、操作がコンテキストを受け取る版です。
// 詳細は RunCtx を参照してください。
func RunValueCtx[T any](ctx context.Context, op func(ctx context.Context) (T, error), opts ...Option) (T, error) {
	var zero T
	if op == nil {
		return zero, ErrNilOperation
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return RunValue(ctx, func() (T, error) { return op(ctx) }, opts...)
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

	var attempts uint

	wrapped := func() (T, error) {
		attempts++
		v, err := op()
		if err == nil {
			return v, nil
		}

		// リトライ不要と判定された場合は backoff にそれ以上試行させない。
		if s.shouldRetry != nil && !s.shouldRetry(err) {
			return v, backoff.Permanent(err)
		}

		// エラーが待機時間を明示している場合は backoff.RetryAfter で次回間隔として
		// 伝える。元のエラーは cause として保持され、打ち切り時に
		// RetryError.LastErr として戻るため失われない。
		if d, ok := retryAfterHint(err); ok {
			return v, backoff.RetryAfter(d, err)
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
		// backoff の既定は 15 分。回数とコンテキストのみで打ち切るため常に明示する。
		backoff.WithMaxElapsedTime(s.maxElapsedTime),
	}
	if s.notify != nil {
		boOpts = append(boOpts, backoff.WithNotify(func(err error, next time.Duration) {
			// backoff から渡るエラーは RetryAfterError の包みを含みうるため、
			// フックには操作が返した元のエラーを渡す。
			s.notify(unwrapRetryAfter(err), attempts, next)
		}))
	}

	v, err := backoff.Retry(ctx, wrapped, boOpts...)
	if err == nil {
		return v, nil
	}
	return v, newError(s.name, attempts, err)
}

// newError は backoff が返したエラーを *Error に変換します。
//
// backoff は失敗時に必ず *backoff.RetryError を返し、最後の操作エラー (LastErr) と
// 打ち切り理由 (Cause) の両方を保持します。Cause は次のように対応付けます。
//
//   - ErrPermanent      : Permanent = true（ErrPermanent に分類される）
//   - ErrExhausted      : 回数上限。Cause は保持しない（ErrExhausted に分類される）
//   - ErrMaxElapsedTime : 経過時間上限。同上
//   - それ以外          : コンテキストの終了原因として Cause に保持する
func newError(name string, attempts uint, err error) *Error {
	e := &Error{Op: name, Attempts: attempts, Err: err}

	re := backoff.AsRetryError(err)
	if re == nil {
		return e
	}
	e.Err = re.LastErr

	switch {
	case errors.Is(re.Cause, backoff.ErrPermanent):
		e.Permanent = true
	case errors.Is(re.Cause, backoff.ErrExhausted), errors.Is(re.Cause, backoff.ErrMaxElapsedTime):
		// 打ち切りは ErrExhausted で表現するため Cause は設定しない。
	default:
		e.Cause = re.Cause
	}
	return e
}

// unwrapRetryAfter は backoff.RetryAfter が包んだ元のエラーを取り出します。
func unwrapRetryAfter(err error) error {
	if ra, ok := errors.AsType[*backoff.RetryAfterError](err); ok {
		if inner := errors.Unwrap(ra); inner != nil {
			return inner
		}
	}
	return err
}

// addSaturating は uint のオーバーフローを飽和させて加算します。
func addSaturating(a, b uint) uint {
	if a > ^uint(0)-b {
		return ^uint(0)
	}
	return a + b
}

// retryAfterHint は、エラーチェーンから DelayHinter による待機時間の指示を取り出します。
func retryAfterHint(err error) (time.Duration, bool) {
	// errors.AsType は T が error を満たすことを要求します。DelayHinter は error を
	// 埋め込まない口なので、ここは errors.As のままにします（go fix は誤変換します）。
	var h DelayHinter
	if errors.As(err, &h) {
		if d := h.RetryAfter(); d > 0 {
			return d, true
		}
	}
	return 0, false
}
