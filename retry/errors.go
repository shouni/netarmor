package retry

import (
	"errors"
	"fmt"
)

// センチネルエラー。呼び出し側は errors.Is で失敗理由を判別できます。
//
// エラーメッセージは Go の慣例に従い英語・小文字・句読点なしで統一しています。
var (
	// ErrNilOperation は、nil の Operation が渡された場合に返されます。
	ErrNilOperation = errors.New("retry: operation is nil")

	// ErrExhausted は、最大試行回数に達しても成功しなかったことを示します。
	ErrExhausted = errors.New("retry: attempts exhausted")

	// ErrPermanent は、ShouldRetryFunc が false を返したためリトライを中止したことを示します。
	ErrPermanent = errors.New("retry: permanent error")
)

// Error はリトライが失敗したときに返される型付きエラーです。
//
// Unwrap が複数のエラーを返すため、次のいずれの判定も可能です。
//
//	errors.Is(err, retry.ErrExhausted)      // 最大試行回数に到達した
//	errors.Is(err, retry.ErrPermanent)      // リトライ不能と判定された
//	errors.Is(err, context.DeadlineExceeded) // コンテキストがタイムアウトした
//	errors.Is(err, myOperationError)         // 操作自体が返した最後のエラー
type Error struct {
	// Op は操作名です。空文字の場合は "operation" として表示されます。
	Op string
	// Attempts は実際に操作を実行した回数です（初回実行を含む）。
	Attempts uint
	// Permanent は ShouldRetryFunc が false を返して中止したかどうかを示します。
	Permanent bool
	// Err は操作が最後に返したエラーです。
	Err error
	// Cause はコンテキストが終了していた場合にその原因を保持します。
	// リトライがコンテキスト以外の理由で終了した場合は nil です。
	Cause error
}

func (e *Error) Error() string {
	switch {
	case e.Permanent:
		return fmt.Sprintf("retry: %s aborted after %d attempt(s): permanent error: %v",
			e.opName(), e.Attempts, e.Err)
	case e.Cause != nil:
		return fmt.Sprintf("retry: %s aborted after %d attempt(s): %v (last error: %v)",
			e.opName(), e.Attempts, e.Cause, e.Err)
	default:
		return fmt.Sprintf("retry: %s failed after %d attempt(s): %v",
			e.opName(), e.Attempts, e.Err)
	}
}

// Unwrap は操作エラー・コンテキスト原因・分類用センチネルをまとめて返します。
func (e *Error) Unwrap() []error {
	errs := make([]error, 0, 3)
	if e.Err != nil {
		errs = append(errs, e.Err)
	}
	if e.Cause != nil {
		errs = append(errs, e.Cause)
	}
	switch {
	case e.Permanent:
		errs = append(errs, ErrPermanent)
	case e.Cause == nil:
		errs = append(errs, ErrExhausted)
	}
	return errs
}

func (e *Error) opName() string {
	if e.Op == "" {
		return "operation"
	}
	return e.Op
}
