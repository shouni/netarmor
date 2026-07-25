package retry_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shouni/netarmor/retry"
)

func ExampleRun() {
	attempts := 0

	err := retry.Run(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	},
		retry.WithName("ExternalAPI"),
		retry.WithInitialInterval(time.Millisecond),
	)

	fmt.Printf("attempts=%d err=%v\n", attempts, err)
	// Output: attempts=3 err=<nil>
}

func ExampleRunValue() {
	body, err := retry.RunValue(context.Background(), func() (string, error) {
		return "response body", nil
	}, retry.WithName("Fetch"))

	fmt.Printf("body=%q err=%v\n", body, err)
	// Output: body="response body" err=<nil>
}

var errServiceDown = errors.New("service down")

// リトライ失敗時のエラーは errors.Is / errors.As で分類できます。
func ExampleRun_errorHandling() {
	err := retry.Run(context.Background(), func() error { return errServiceDown },
		retry.WithName("Payment"),
		retry.WithMaxRetries(1),
		retry.WithInitialInterval(time.Millisecond),
	)

	fmt.Println("exhausted:", errors.Is(err, retry.ErrExhausted))
	fmt.Println("original:", errors.Is(err, errServiceDown))

	if re, ok := errors.AsType[*retry.Error](err); ok {
		fmt.Println("attempts:", re.Attempts)
	}
	// Output:
	// exhausted: true
	// original: true
	// attempts: 2
}

// ShouldRetryFunc が false を返すと、その時点でリトライを打ち切ります。
func ExampleWithShouldRetry() {
	attempts := 0
	errUnauthorized := errors.New("401 unauthorized")

	err := retry.Run(context.Background(), func() error {
		attempts++
		return errUnauthorized
	},
		retry.WithInitialInterval(time.Millisecond),
		retry.WithShouldRetry(func(err error) bool {
			// 認証エラーは何度試しても直らないためリトライしない
			return !errors.Is(err, errUnauthorized)
		}),
	)

	fmt.Println("attempts:", attempts)
	fmt.Println("permanent:", errors.Is(err, retry.ErrPermanent))
	// Output:
	// attempts: 1
	// permanent: true
}

func ExampleWithNotify() {
	_ = retry.Run(context.Background(), func() error { return errors.New("boom") },
		retry.WithMaxRetries(2),
		retry.WithInitialInterval(time.Millisecond),
		retry.WithMaxInterval(time.Millisecond),
		retry.WithRandomizationFactor(0), // 出力を決定的にするためジッタを無効化
		retry.WithNotify(func(err error, attempt uint, next time.Duration) {
			fmt.Printf("attempt %d failed: %v (retrying in %v)\n", attempt, err, next)
		}),
	)
	// Output:
	// attempt 1 failed: boom (retrying in 1ms)
	// attempt 2 failed: boom (retrying in 1ms)
}
