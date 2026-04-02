package cef_test

import (
	"testing"

	cef "github.com/ubyte-source/go-cef"
)

func TestUnescapeHeader(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"no_escape", "hello world", "hello world"},
		{"escaped_pipe", `detected a \| in message`, "detected a | in message"},
		{"escaped_backslash", `name with \\`, `name with \`},
		{"both_escapes", `a \| b \\ c`, `a | b \ c`},
		{"multiple_pipes", `\|foo\|bar\|`, "|foo|bar|"},
		{"double_backslash_pipe", `test \\\| end`, `test \| end`},
		{"empty", "", ""},
		{"just_backslash_at_end", `test\`, `test\`},
		{"unknown_escape_permissive", `test\n kept`, `test\n kept`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(cef.UnescapeHeader([]byte(tt.raw), nil))
			if got != tt.want {
				t.Errorf("cef.UnescapeHeader(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestUnescapeExtValue(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"no_escape", "hello world", "hello world"},
		{"escaped_equals", `hello\=world`, "hello=world"},
		{"escaped_backslash", `C:\\Windows\\System32`, `C:\Windows\System32`},
		{"escaped_newline", `line1\nline2`, "line1\nline2"},
		{"escaped_cr", `line1\rline2`, "line1\rline2"},
		{"all_escapes", `a\=b\\c\nd\re`, "a=b\\c\nd\re"},
		{"double_backslash_before_equals", `test\\=val`, `test\=val`},
		{"triple_backslash_equals", `test\\\=val`, `test\=val`},
		{"empty", "", ""},
		{"just_backslash_at_end", `test\`, `test\`},
		{"unknown_escape_permissive", `test\x kept`, `test\x kept`},
		{"pipe_not_escaped", "contains | pipe", "contains | pipe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(cef.UnescapeExtValue([]byte(tt.raw), nil))
			if got != tt.want {
				t.Errorf("cef.UnescapeExtValue(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestUnescapeHeaderZeroAlloc(t *testing.T) {
	// When there are no escapes, UnescapeHeader should return the original slice.
	raw := []byte("no escapes here")
	got := cef.UnescapeHeader(raw, nil)
	if &got[0] != &raw[0] {
		t.Error("expected zero-alloc fast path: same underlying array")
	}
}

func TestUnescapeExtValueZeroAlloc(t *testing.T) {
	raw := []byte("no escapes here")
	got := cef.UnescapeExtValue(raw, nil)
	if &got[0] != &raw[0] {
		t.Error("expected zero-alloc fast path: same underlying array")
	}
}

func TestUnescapeWithDstBuffer(t *testing.T) {
	raw := []byte(`hello\=world`)
	dst := make([]byte, 0, 64) // pre-allocated buffer
	got := cef.UnescapeExtValue(raw, dst)
	if string(got) != "hello=world" {
		t.Errorf("got %q, want %q", got, "hello=world")
	}
}

func TestUnescapeIntegration(t *testing.T) {
	// Full parse + unescape pipeline.
	m := cef.NewParser()
	input := []byte(
		`CEF:0|security|threatmanager|1.0|100|` +
			`detected a \| in message|10|` +
			`msg=equation is 2+2\=4 filePath=C:\\Windows\\System32`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Header unescape.
	name := string(cef.UnescapeHeader(e.Bytes(e.Name), nil))
	if name != "detected a | in message" {
		t.Errorf("name: got %q, want %q", name, "detected a | in message")
	}

	// Extension unescape.
	if span, ok := e.ExtString("msg"); ok {
		val := string(cef.UnescapeExtValue(e.Bytes(span), nil))
		if val != "equation is 2+2=4" {
			t.Errorf("msg: got %q, want %q", val, "equation is 2+2=4")
		}
	} else {
		t.Fatal("expected ext msg")
	}

	if span, ok := e.ExtString("filePath"); ok {
		val := string(cef.UnescapeExtValue(e.Bytes(span), nil))
		if val != `C:\Windows\System32` {
			t.Errorf("filePath: got %q, want %q", val, `C:\Windows\System32`)
		}
	} else {
		t.Fatal("expected ext filePath")
	}
}

func BenchmarkUnescapeHeaderNoEscape(b *testing.B) {
	raw := []byte("no escapes here at all just plain text")
	b.ReportAllocs()
	for b.Loop() {
		cef.UnescapeHeader(raw, nil)
	}
}

func BenchmarkUnescapeHeaderWithEscapes(b *testing.B) {
	raw := []byte(`detected a \| in message with \\ backslash`)
	dst := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		cef.UnescapeHeader(raw, dst)
	}
}

func BenchmarkUnescapeExtValueNoEscape(b *testing.B) {
	raw := []byte("plain text value without any escapes at all")
	b.ReportAllocs()
	for b.Loop() {
		cef.UnescapeExtValue(raw, nil)
	}
}

func BenchmarkUnescapeExtValueWithEscapes(b *testing.B) {
	raw := []byte(`C:\\Windows\\System32\\file\=name\nwith newline`)
	dst := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		cef.UnescapeExtValue(raw, dst)
	}
}
