package securenet

import "testing"

func TestRedactURLString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no query", "https://example.com/path", "https://example.com/path"},
		{"query and fragment", "https://example.com/p?sig=abc#frag", "https://example.com/p?REDACTED"},
		{"empty query", "https://example.com/p?", "https://example.com/p?REDACTED"},
		{"password", "https://user:pw@example.com/", "https://user:xxxxx@example.com/"},
		{"query in unparsable input", "https://example.com/%zz?sig=abc", "https://example.com/%zz?REDACTED"},
		{"userinfo in unparsable input", "https://user:pw@example.com/%zz", "https://xxxxx@example.com/%zz"},
		{"keeps @ in path of unparsable input", "https://example.com/%zz/a@b", "https://example.com/%zz/a@b"},
		{"unparsable input without scheme", "://invalid", "://invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactURLString(tt.in); got != tt.want {
				t.Errorf("redactURLString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
