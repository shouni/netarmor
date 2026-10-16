package securenet

import "testing"

func TestRedactURLString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"クエリなし", "https://example.com/path", "https://example.com/path"},
		{"クエリとフラグメント", "https://example.com/p?sig=abc#frag", "https://example.com/p?REDACTED"},
		{"空のクエリ", "https://example.com/p?", "https://example.com/p?REDACTED"},
		{"パスワード", "https://user:pw@example.com/", "https://user:xxxxx@example.com/"},
		{"解析できない入力のクエリ", "https://example.com/%zz?sig=abc", "https://example.com/%zz?REDACTED"},
		{"解析できない入力のユーザー情報", "https://user:pw@example.com/%zz", "https://xxxxx@example.com/%zz"},
		{"解析できない入力のパスの @ は残す", "https://example.com/%zz/a@b", "https://example.com/%zz/a@b"},
		{"スキームのない解析できない入力", "://invalid", "://invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactURLString(tt.in); got != tt.want {
				t.Errorf("redactURLString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
