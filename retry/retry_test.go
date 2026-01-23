package retry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDo(t *testing.T) {
	ctx := context.Background()

	// 短めのインターバルでテストを高速化
	cfg := Config{
		MaxRetries:      2,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
	}

	t.Run("成功: 1回失敗した後にリトライで成功すること", func(t *testing.T) {
		calls := 0
		op := func() error {
			calls++
			if calls == 1 {
				return errors.New("temporary error")
			}
			return nil
		}

		err := Do(ctx, cfg, "TestOp", op, func(err error) bool { return true })

		if err != nil {
			t.Errorf("期待しないエラーが発生しました: %v", err)
		}
		if calls != 2 {
			t.Errorf("リトライ回数が不正です: 期待 2, 実績 %d", calls)
		}
	})

	t.Run("失敗: 最大リトライ回数を超えてエラーが返ること", func(t *testing.T) {
		calls := 0
		errExpected := errors.New("persistent error")
		op := func() error {
			calls++
			return errExpected
		}

		err := Do(ctx, cfg, "TestOp", op, func(err error) bool { return true })

		if err == nil {
			t.Fatal("エラーが返ることを期待していましたが、nil です")
		}
		if !strings.Contains(err.Error(), "最大リトライ回数") {
			t.Errorf("エラーメッセージが不正です: %v", err)
		}
		if !errors.Is(err, errExpected) {
			t.Errorf("元のエラーがラップされていません: %v", err)
		}
		// 初回(1) + リトライ(2) = 計3回
		if calls != 3 {
			t.Errorf("試行回数が不正です: 期待 3, 実績 %d", calls)
		}
	})

	t.Run("中断: ShouldRetryFuncがfalseを返した時に即座に中止すること", func(t *testing.T) {
		calls := 0
		fatalErr := errors.New("fatal error")
		op := func() error {
			calls++
			return fatalErr
		}

		shouldRetry := func(err error) bool {
			// 特定のエラーメッセージならリトライしない
			return !strings.Contains(err.Error(), "fatal")
		}

		err := Do(ctx, cfg, "TestOp", op, shouldRetry)

		if err == nil {
			t.Fatal("エラーを期待していましたが、nil です")
		}
		if !strings.Contains(err.Error(), "致命的なエラーのため中止") {
			t.Errorf("エラーメッセージが中断用ではありません: %v", err)
		}
		if calls != 1 {
			t.Errorf("即座に中断されるべきですが、%d 回実行されました", calls)
		}
	})

	t.Run("キャンセル: Contextがキャンセルされた場合に中断すること", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel() // 即座にキャンセル

		op := func() error {
			return errors.New("any error")
		}

		err := Do(cancelCtx, cfg, "TestOp", op, nil)

		if err == nil {
			t.Fatal("キャンセルによるエラーを期待していましたが、nil です")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("context.Canceled を期待していましたが、異なります: %v", err)
		}
	})
}
