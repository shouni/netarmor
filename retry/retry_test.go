package retry_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shouni/netarmor/retry"
)

// 短めのインターバルでテストを高速化する。
// 既定値 (5s/30s) に依存するテストを書かないこと。
func fastOpts(extra ...retry.Option) []retry.Option {
	return append([]retry.Option{
		retry.WithMaxRetries(2),
		retry.WithInitialInterval(10 * time.Millisecond),
		retry.WithMaxInterval(50 * time.Millisecond),
		retry.WithRandomizationFactor(0),
	}, extra...)
}

func TestRun(t *testing.T) {
	ctx := context.Background()

	t.Run("成功: 1回失敗した後にリトライで成功すること", func(t *testing.T) {
		calls := 0
		err := retry.Run(ctx, func() error {
			calls++
			if calls == 1 {
				return errors.New("temporary error")
			}
			return nil
		}, fastOpts()...)

		if err != nil {
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		if calls != 2 {
			t.Errorf("リトライ回数が不正です: 期待 2, 実績 %d", calls)
		}
	})

	t.Run("失敗: 最大リトライ回数を超えてエラーが返ること", func(t *testing.T) {
		calls := 0
		errExpected := errors.New("persistent error")
		err := retry.Run(ctx, func() error {
			calls++
			return errExpected
		}, fastOpts(retry.WithName("TestOp"))...)

		if !errors.Is(err, retry.ErrExhausted) {
			t.Errorf("ErrExhausted を期待していましたが、異なります: %v", err)
		}
		if !errors.Is(err, errExpected) {
			t.Errorf("元のエラーがラップされていません: %v", err)
		}
		if !strings.Contains(err.Error(), "TestOp") {
			t.Errorf("操作名がエラーメッセージに含まれていません: %v", err)
		}
		// 初回(1) + リトライ(2) = 計3回
		if calls != 3 {
			t.Errorf("試行回数が不正です: 期待 3, 実績 %d", calls)
		}

		re, ok := errors.AsType[*retry.Error](err)
		if !ok {
			t.Fatalf("*retry.Error を期待していましたが、異なります: %v", err)
		}
		if re.Attempts != 3 {
			t.Errorf("Attempts が不正です: 期待 3, 実績 %d", re.Attempts)
		}
		if re.Permanent {
			t.Error("Permanent は false であるべきです")
		}
	})

	t.Run("中断: ShouldRetryFuncがfalseを返した時に即座に中止すること", func(t *testing.T) {
		calls := 0
		fatalErr := errors.New("fatal error")
		shouldRetry := func(err error) bool {
			return !strings.Contains(err.Error(), "fatal")
		}

		err := retry.Run(ctx, func() error {
			calls++
			return fatalErr
		}, fastOpts(retry.WithShouldRetry(shouldRetry))...)

		if !errors.Is(err, retry.ErrPermanent) {
			t.Errorf("ErrPermanent を期待していましたが、異なります: %v", err)
		}
		if errors.Is(err, retry.ErrExhausted) {
			t.Error("永続的エラーでは ErrExhausted になってはいけません")
		}
		if !errors.Is(err, fatalErr) {
			t.Errorf("元のエラーがラップされていません: %v", err)
		}
		if calls != 1 {
			t.Errorf("即座に中断されるべきですが、%d 回実行されました", calls)
		}
	})

	t.Run("キャンセル: Contextがキャンセルされた場合に中断すること", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()

		opErr := errors.New("any error")
		err := retry.Run(cancelCtx, func() error { return opErr }, fastOpts()...)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("context.Canceled を期待していましたが、異なります: %v", err)
		}
		// backoff v5 はコンテキスト終了時に操作エラーを捨てるため、
		// *Error 側で保持できていることを確認する。
		if !errors.Is(err, opErr) {
			t.Errorf("最後の操作エラーが失われています: %v", err)
		}
		if errors.Is(err, retry.ErrExhausted) {
			t.Error("コンテキスト中断では ErrExhausted になってはいけません")
		}
	})

	t.Run("キャンセル: WithCancelCause の原因が伝播すること", func(t *testing.T) {
		causeErr := errors.New("shutting down")
		cancelCtx, cancel := context.WithCancelCause(context.Background())
		cancel(causeErr)

		err := retry.Run(cancelCtx, func() error { return errors.New("any error") }, fastOpts()...)

		if !errors.Is(err, causeErr) {
			t.Errorf("context.Cause が伝播していません: %v", err)
		}
	})

	t.Run("タイムアウト: Contextのデッドラインで打ち切られること", func(t *testing.T) {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()

		err := retry.Run(timeoutCtx, func() error { return errors.New("slow failure") },
			retry.WithMaxRetries(100),
			retry.WithInitialInterval(10*time.Millisecond),
			retry.WithMaxInterval(10*time.Millisecond),
			retry.WithRandomizationFactor(0),
		)

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("context.DeadlineExceeded を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("WithMaxRetries(0) はリトライせず1回だけ実行すること", func(t *testing.T) {
		calls := 0
		err := retry.Run(ctx, func() error {
			calls++
			return errors.New("boom")
		}, retry.WithMaxRetries(0), retry.WithInitialInterval(time.Millisecond))

		if calls != 1 {
			t.Errorf("試行回数が不正です: 期待 1, 実績 %d", calls)
		}
		if !errors.Is(err, retry.ErrExhausted) {
			t.Errorf("ErrExhausted を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("WithMaxAttempts は初回実行を含む回数であること", func(t *testing.T) {
		calls := 0
		_ = retry.Run(ctx, func() error {
			calls++
			return errors.New("boom")
		}, retry.WithMaxAttempts(2), retry.WithInitialInterval(time.Millisecond),
			retry.WithRandomizationFactor(0))

		if calls != 2 {
			t.Errorf("試行回数が不正です: 期待 2, 実績 %d", calls)
		}
	})

	t.Run("WithMaxAttempts(0) は1回として扱われること", func(t *testing.T) {
		calls := 0
		_ = retry.Run(ctx, func() error {
			calls++
			return errors.New("boom")
		}, retry.WithMaxAttempts(0), retry.WithInitialInterval(time.Millisecond))

		if calls != 1 {
			t.Errorf("試行回数が不正です: 期待 1, 実績 %d", calls)
		}
	})

	t.Run("WithNotify が各リトライ前に呼ばれること", func(t *testing.T) {
		var attempts []uint
		var waits []time.Duration

		_ = retry.Run(ctx, func() error { return errors.New("boom") },
			fastOpts(retry.WithNotify(func(_ error, attempt uint, next time.Duration) {
				attempts = append(attempts, attempt)
				waits = append(waits, next)
			}))...)

		// 3回試行 = リトライ前の通知は2回
		if len(attempts) != 2 {
			t.Fatalf("通知回数が不正です: 期待 2, 実績 %d", len(attempts))
		}
		if attempts[0] != 1 || attempts[1] != 2 {
			t.Errorf("attempt の値が不正です: %v", attempts)
		}
		for i, w := range waits {
			if w <= 0 {
				t.Errorf("待機時間が不正です (index %d): %v", i, w)
			}
		}
	})

	t.Run("WithRandomizationFactor(0) で待機時間が決定的になること", func(t *testing.T) {
		var waits []time.Duration

		_ = retry.Run(ctx, func() error { return errors.New("boom") },
			retry.WithMaxRetries(2),
			retry.WithInitialInterval(10*time.Millisecond),
			retry.WithMaxInterval(time.Second),
			retry.WithMultiplier(2),
			retry.WithRandomizationFactor(0),
			retry.WithNotify(func(_ error, _ uint, next time.Duration) {
				waits = append(waits, next)
			}),
		)

		if len(waits) != 2 {
			t.Fatalf("通知回数が不正です: 期待 2, 実績 %d", len(waits))
		}
		if waits[0] != 10*time.Millisecond {
			t.Errorf("初回の待機時間が不正です: %v", waits[0])
		}
		if waits[1] != 20*time.Millisecond {
			t.Errorf("Multiplier が適用されていません: %v", waits[1])
		}
	})

	t.Run("WithMaxElapsedTime で経過時間により打ち切られること", func(t *testing.T) {
		calls := 0
		_ = retry.Run(ctx, func() error {
			calls++
			return errors.New("boom")
		},
			retry.WithMaxRetries(1000),
			retry.WithInitialInterval(20*time.Millisecond),
			retry.WithMaxInterval(20*time.Millisecond),
			retry.WithRandomizationFactor(0),
			retry.WithMaxElapsedTime(50*time.Millisecond),
		)

		if calls == 0 || calls > 5 {
			t.Errorf("経過時間で打ち切られていません: %d 回実行されました", calls)
		}
	})

	t.Run("失敗: nil Operation は即座にエラーになること", func(t *testing.T) {
		if err := retry.Run(ctx, nil); !errors.Is(err, retry.ErrNilOperation) {
			t.Errorf("ErrNilOperation を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("nil context は Background として扱われること", func(t *testing.T) {
		// 誤って nil を渡されても panic しないことの確認。
		var nilCtx context.Context
		if err := retry.Run(nilCtx, func() error { return nil }); err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
	})
}

// rateLimitedError は DelayHinter を実装するテスト用エラーです。
type rateLimitedError struct{ after time.Duration }

func (e *rateLimitedError) Error() string             { return "rate limited" }
func (e *rateLimitedError) RetryAfter() time.Duration { return e.after }

func TestRetryAfterHint(t *testing.T) {
	ctx := context.Background()

	t.Run("ヒントが次の待機時間として使われること", func(t *testing.T) {
		hinted := &rateLimitedError{after: 80 * time.Millisecond}
		var waits []time.Duration

		_ = retry.Run(ctx, func() error { return hinted },
			retry.WithMaxRetries(1),
			retry.WithInitialInterval(time.Millisecond),
			retry.WithRandomizationFactor(0),
			retry.WithNotify(func(_ error, _ uint, next time.Duration) {
				waits = append(waits, next)
			}),
		)

		if len(waits) != 1 {
			t.Fatalf("通知回数が不正です: 期待 1, 実績 %d", len(waits))
		}
		if waits[0] != 80*time.Millisecond {
			t.Errorf("ヒントが待機時間に反映されていません: %v", waits[0])
		}
	})

	t.Run("ラップされたヒントも errors.As で検出されること", func(t *testing.T) {
		hinted := &rateLimitedError{after: 60 * time.Millisecond}
		var waits []time.Duration

		_ = retry.Run(ctx, func() error { return fmt.Errorf("request failed: %w", hinted) },
			retry.WithMaxRetries(1),
			retry.WithInitialInterval(time.Millisecond),
			retry.WithRandomizationFactor(0),
			retry.WithNotify(func(_ error, _ uint, next time.Duration) {
				waits = append(waits, next)
			}),
		)

		if len(waits) != 1 || waits[0] != 60*time.Millisecond {
			t.Errorf("ラップされたヒントが反映されていません: %v", waits)
		}
	})

	t.Run("0以下のヒントは無視され通常のバックオフになること", func(t *testing.T) {
		hinted := &rateLimitedError{after: 0}
		var waits []time.Duration

		_ = retry.Run(ctx, func() error { return hinted },
			retry.WithMaxRetries(1),
			retry.WithInitialInterval(10*time.Millisecond),
			retry.WithRandomizationFactor(0),
			retry.WithNotify(func(_ error, _ uint, next time.Duration) {
				waits = append(waits, next)
			}),
		)

		if len(waits) != 1 || waits[0] != 10*time.Millisecond {
			t.Errorf("0のヒントは無視されるべきです: %v", waits)
		}
	})

	t.Run("フックと最終エラーには元のエラーが渡ること", func(t *testing.T) {
		hinted := &rateLimitedError{after: time.Millisecond}
		var notified []error

		err := retry.Run(ctx, func() error { return hinted },
			retry.WithMaxRetries(1),
			retry.WithInitialInterval(time.Millisecond),
			retry.WithRandomizationFactor(0),
			retry.WithNotify(func(err error, _ uint, _ time.Duration) {
				notified = append(notified, err)
			}),
		)

		if len(notified) != 1 || !errors.Is(notified[0], hinted) {
			t.Errorf("フックに元のエラーが渡っていません: %v", notified)
		}
		re, ok := errors.AsType[*retry.Error](err)
		if !ok {
			t.Fatalf("*retry.Error を期待していましたが、異なります: %v", err)
		}
		if re.Err != hinted { //nolint:errorlint // 連結表現でなく元のエラーそのものであることの検証
			t.Errorf("Error.Err が元のエラーではありません: %v", re.Err)
		}
	})

	t.Run("ShouldRetryFunc の打ち切りがヒントより優先されること", func(t *testing.T) {
		calls := 0
		err := retry.Run(ctx, func() error {
			calls++
			return &rateLimitedError{after: time.Millisecond}
		},
			retry.WithMaxRetries(3),
			retry.WithInitialInterval(time.Millisecond),
			retry.WithShouldRetry(func(error) bool { return false }),
		)

		if calls != 1 {
			t.Errorf("即座に中断されるべきですが、%d 回実行されました", calls)
		}
		if !errors.Is(err, retry.ErrPermanent) {
			t.Errorf("ErrPermanent を期待していましたが、異なります: %v", err)
		}
	})
}

func TestRunValue(t *testing.T) {
	ctx := context.Background()

	t.Run("成功時に値を返すこと", func(t *testing.T) {
		calls := 0
		got, err := retry.RunValue(ctx, func() (string, error) {
			calls++
			if calls == 1 {
				return "", errors.New("temporary")
			}
			return "ok", nil
		}, fastOpts()...)

		if err != nil {
			t.Fatalf("期待しないエラーが発生しました: %v", err)
		}
		if got != "ok" {
			t.Errorf("戻り値が不正です: 期待 \"ok\", 実績 %q", got)
		}
	})

	t.Run("失敗時はゼロ値とエラーを返すこと", func(t *testing.T) {
		got, err := retry.RunValue(ctx, func() (int, error) {
			return 0, errors.New("boom")
		}, fastOpts()...)

		if got != 0 {
			t.Errorf("ゼロ値を期待していましたが、実績 %d", got)
		}
		if !errors.Is(err, retry.ErrExhausted) {
			t.Errorf("ErrExhausted を期待していましたが、異なります: %v", err)
		}
	})

	t.Run("失敗: nil Operation は即座にエラーになること", func(t *testing.T) {
		_, err := retry.RunValue[int](ctx, nil)
		if !errors.Is(err, retry.ErrNilOperation) {
			t.Errorf("ErrNilOperation を期待していましたが、異なります: %v", err)
		}
	})
}

func TestErrorFormatting(t *testing.T) {
	base := errors.New("boom")

	tests := []struct {
		name string
		err  *retry.Error
		want string
	}{
		{"Exhausted", &retry.Error{Op: "API", Attempts: 3, Err: base}, "failed after 3 attempt(s)"},
		{"Permanent", &retry.Error{Op: "API", Attempts: 1, Permanent: true, Err: base}, "permanent error"},
		{"Context", &retry.Error{Op: "API", Attempts: 2, Err: base, Cause: context.Canceled}, "last error: boom"},
		{"NoOpName", &retry.Error{Attempts: 1, Err: base}, "operation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.want) {
				t.Errorf("メッセージに %q が含まれていません: %s", tt.want, tt.err.Error())
			}
		})
	}
}
