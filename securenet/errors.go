package securenet

import (
	"errors"
	"fmt"
	"net/netip"
)

// センチネルエラー。呼び出し側は errors.Is で失敗理由を判別できます。
//
// エラーメッセージは Go の慣例に従い英語・小文字・句読点なしで統一しています。
// 日本語で表示したい場合は errors.Is / errors.As で分類した上で、
// 呼び出し側でメッセージを組み立ててください。
var (
	// ErrRestrictedIP は、名前解決の結果が制限されたネットワークに含まれていたことを示します。
	// 詳細な IP アドレスを取得するには errors.As で *BlockedIPError を取り出してください。
	ErrRestrictedIP = errors.New("securenet: restricted network")

	// ErrDisallowedScheme は、URL のスキームが許可されていないことを示します。
	ErrDisallowedScheme = errors.New("securenet: disallowed scheme")

	// ErrEmptyHost は、URL にホスト名が含まれていないことを示します。
	ErrEmptyHost = errors.New("securenet: empty host")

	// ErrNoAddresses は、名前解決には成功したが結果が空だったことを示します。
	ErrNoAddresses = errors.New("securenet: hostname resolved to no addresses")

	// ErrInvalidURL は、URL のパースに失敗したことを示します。
	ErrInvalidURL = errors.New("securenet: invalid URL")

	// ErrTooManyRedirects は、リダイレクトの追従回数が上限に達したことを示します。
	ErrTooManyRedirects = errors.New("securenet: too many redirects")

	// ErrRedirectDowngrade は、https から http へのリダイレクトを拒否したことを示します。
	ErrRedirectDowngrade = errors.New("securenet: redirect downgrade")
)

// BlockedIPError は、制限されたネットワークへの接続が遮断されたことを表します。
// errors.Is(err, ErrRestrictedIP) が true になります。
type BlockedIPError struct {
	// Host は検証対象となったホスト名です。
	Host string
	// Addr は制限対象と判定された IP アドレスです。
	Addr netip.Addr
}

func (e *BlockedIPError) Error() string {
	return fmt.Sprintf("securenet: restricted network: host %q resolved to %s", e.Host, e.Addr)
}

// Unwrap は ErrRestrictedIP を返し、errors.Is による分類を可能にします。
func (e *BlockedIPError) Unwrap() error { return ErrRestrictedIP }

// SchemeError は、許可されていないスキームが指定されたことを表します。
// errors.Is(err, ErrDisallowedScheme) が true になります。
type SchemeError struct {
	// Scheme は拒否されたスキーム（小文字化済み）です。
	Scheme string
}

func (e *SchemeError) Error() string {
	return fmt.Sprintf("securenet: disallowed scheme %q", e.Scheme)
}

// Unwrap は ErrDisallowedScheme を返し、errors.Is による分類を可能にします。
func (e *SchemeError) Unwrap() error { return ErrDisallowedScheme }

// ResolveError は、ホスト名の解決に失敗したことを表します。
// 元となった DNS エラーは Unwrap で取得できます。
type ResolveError struct {
	// Host は解決に失敗したホスト名です。
	Host string
	// Err はリゾルバが返した元のエラーです。
	Err error
}

func (e *ResolveError) Error() string {
	return fmt.Sprintf("securenet: lookup %q: %v", e.Host, e.Err)
}

// Unwrap はリゾルバが返した元のエラーを返します。
func (e *ResolveError) Unwrap() error { return e.Err }

// URLError は、URL のパースに失敗したことを表します。
// errors.Is(err, ErrInvalidURL) が true になります。
type URLError struct {
	// URL はパースに失敗した入力文字列です。
	URL string
	// Err は url パッケージが返した元のエラーです。nil の場合もあります。
	Err error
}

func (e *URLError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("securenet: invalid URL %q", e.URL)
	}
	return fmt.Sprintf("securenet: invalid URL %q: %v", e.URL, e.Err)
}

// Unwrap は ErrInvalidURL と元のパースエラーの両方を返し、
// errors.Is による分類と原因エラーの取得を同時に可能にします。
func (e *URLError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrInvalidURL}
	}
	return []error{ErrInvalidURL, e.Err}
}

// TooManyRedirectsError は、リダイレクトの追従を上限で打ち切ったことを表します。
// errors.Is(err, ErrTooManyRedirects) が true になります。
//
// このエラーは *http.Client の CheckRedirect から返るため、呼び出し側には
// *url.Error に包まれて届きます。errors.Is / errors.As はその包みを透過します。
type TooManyRedirectsError struct {
	// Max は設定されていた追従回数の上限です。
	Max int
}

func (e *TooManyRedirectsError) Error() string {
	return fmt.Sprintf("securenet: stopped after %d redirects", e.Max)
}

// Unwrap は ErrTooManyRedirects を返し、errors.Is による分類を可能にします。
func (e *TooManyRedirectsError) Unwrap() error { return ErrTooManyRedirects }

// RedirectDowngradeError は、https から http へのリダイレクト追従を拒否したことを表します。
// errors.Is(err, ErrRedirectDowngrade) が true になります。
type RedirectDowngradeError struct {
	// URL はリダイレクト先です。認証情報は伏せ字にした表現を保持します。
	URL string
}

func (e *RedirectDowngradeError) Error() string {
	return fmt.Sprintf("securenet: refusing redirect downgrade from https to http (%s)", e.URL)
}

// Unwrap は ErrRedirectDowngrade を返し、errors.Is による分類を可能にします。
func (e *RedirectDowngradeError) Unwrap() error { return ErrRedirectDowngrade }
