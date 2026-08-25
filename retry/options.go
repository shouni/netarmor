package retry

import (
	"context"
	"time"
)

const (
	// DefaultMaxRetries は既定の最大リトライ回数です（初回実行を除く）。
	DefaultMaxRetries = 3
	// InitialBackoffInterval は既定の初期バックオフ間隔です。
	InitialBackoffInterval = 5 * time.Second
	// MaxBackoffInterval は既定の最大バックオフ間隔です。
	MaxBackoffInterval = 30 * time.Second
	// DefaultMultiplier は既定のバックオフ倍率です。
	DefaultMultiplier = 1.5
	// DefaultRandomizationFactor は既定のジッタ係数です。
	// 実際の待機時間は算出値の ±50% の範囲でランダムに散らされます。
	DefaultRandomizationFactor = 0.5
)

// Operation はリトライ可能な処理を表す関数です。
type Operation func() error

// OperationCtx は、コンテキストを受け取るリトライ可能な処理を表す関数です。
// RunCtx / RunValueCtx から、呼び出し側が渡した ctx がそのまま渡されます。
type OperationCtx func(ctx context.Context) error

// ShouldRetryFunc はエラーを受け取り、そのエラーがリトライ可能かどうかを判定します。
// false を返すとリトライを打ち切り、Error.Permanent が true になります。
type ShouldRetryFunc func(error) bool

// NotifyFunc はリトライ直前に呼び出されます。
// attempt は失敗した試行の回数（1 始まり）、next は次の試行までの待機時間です。
// ログ出力やメトリクス送信に使用してください。
type NotifyFunc func(err error, attempt uint, next time.Duration)

// DelayHinter は、次のリトライまで最低限待つべき時間をエラー自身が
// 提示するためのインターフェースです。HTTP 429/503 の Retry-After ヘッダーの
// ように、サーバが待機時間を指定してきた場合にエラー型へ実装してください。
//
// 判定は errors.As で行われるため、ラップされたエラーでも機能します。
// RetryAfter が正の値を返すと、次の待機時間は指数バックオフの算出値の代わりに
// その値になり、以降のバックオフ計算はリセットされます。0 以下の値は無視されます。
// WithMaxElapsedTime やコンテキストによる打ち切りは通常どおり適用されます。
type DelayHinter interface {
	RetryAfter() time.Duration
}

// settings は Run / RunValue の内部設定です。
type settings struct {
	name                string
	maxRetries          uint
	initialInterval     time.Duration
	maxInterval         time.Duration
	multiplier          float64
	randomizationFactor float64
	maxElapsedTime      time.Duration
	shouldRetry         ShouldRetryFunc
	notify              NotifyFunc
}

// Option は Run / RunValue の挙動を調整します。
type Option func(*settings)

func newSettings(opts []Option) *settings {
	s := &settings{
		maxRetries:          DefaultMaxRetries,
		initialInterval:     InitialBackoffInterval,
		maxInterval:         MaxBackoffInterval,
		multiplier:          DefaultMultiplier,
		randomizationFactor: DefaultRandomizationFactor,
		// 回数ベースのリトライを優先するため、経過時間による打ち切りは既定で無効。
		maxElapsedTime: 0,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// WithName は操作名を設定します。エラーメッセージに含まれます。
func WithName(name string) Option {
	return func(s *settings) { s.name = name }
}

// WithMaxRetries は初回実行に加えて行うリトライの最大回数を設定します。
// 0 を指定すると「リトライせず 1 回だけ実行する」という意味になります。
func WithMaxRetries(n uint) Option {
	return func(s *settings) { s.maxRetries = n }
}

// WithMaxAttempts は初回実行を含めた最大試行回数を設定します。
// 1 はリトライなしを意味します。0 は 1 として扱われます。
func WithMaxAttempts(n uint) Option {
	return func(s *settings) {
		if n == 0 {
			n = 1
		}
		s.maxRetries = n - 1
	}
}

// WithInitialInterval は初回リトライまでの待機時間を設定します。負値は無視されます。
func WithInitialInterval(d time.Duration) Option {
	return func(s *settings) {
		if d >= 0 {
			s.initialInterval = d
		}
	}
}

// WithMaxInterval は待機時間の上限を設定します。負値は無視されます。
func WithMaxInterval(d time.Duration) Option {
	return func(s *settings) {
		if d >= 0 {
			s.maxInterval = d
		}
	}
}

// WithMultiplier は待機時間の増加倍率を設定します。1.0 で固定間隔になります。
func WithMultiplier(m float64) Option {
	return func(s *settings) {
		if m > 0 {
			s.multiplier = m
		}
	}
}

// WithRandomizationFactor はジッタの大きさを [0, 1] で設定します。
// 0 を指定するとジッタなし（完全な固定スケジュール）になります。
// 範囲外の値は無視されます。
func WithRandomizationFactor(f float64) Option {
	return func(s *settings) {
		if f >= 0 && f <= 1 {
			s.randomizationFactor = f
		}
	}
}

// WithMaxElapsedTime はリトライ全体の経過時間の上限を設定します。
// 0 を指定すると無効化され、回数とコンテキストのみで打ち切られます（既定）。
// 負値は無視されます。
func WithMaxElapsedTime(d time.Duration) Option {
	return func(s *settings) {
		if d >= 0 {
			s.maxElapsedTime = d
		}
	}
}

// WithShouldRetry はリトライすべきエラーかどうかの判定関数を設定します。
// 未設定の場合はすべてのエラーがリトライ対象になります。
func WithShouldRetry(fn ShouldRetryFunc) Option {
	return func(s *settings) { s.shouldRetry = fn }
}

// WithNotify はリトライ直前に呼ばれるフックを設定します。
func WithNotify(fn NotifyFunc) Option {
	return func(s *settings) { s.notify = fn }
}
