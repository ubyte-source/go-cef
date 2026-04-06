package cef

import (
	"strings"
	"testing"
)

func TestIsKeyChar(t *testing.T) {
	valid := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-[]"
	for _, c := range []byte(valid) {
		if !isKeyChar(c) {
			t.Errorf("isKeyChar(%q) = false, want true", rune(c))
		}
	}
	invalid := " \t\n=|\\/@#$%^&*(){}:;'\"<>,?!"
	for _, c := range []byte(invalid) {
		if isKeyChar(c) {
			t.Errorf("isKeyChar(%q) = true, want false", rune(c))
		}
	}
}

func TestIsKeyBitsetCorrectness(t *testing.T) {
	var ref [256]bool
	for c := byte('a'); c <= 'z'; c++ {
		ref[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		ref[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		ref[c] = true
	}
	for _, c := range []byte{'.', '_', '-', '[', ']'} {
		ref[c] = true
	}
	for i := 0; i < 256; i++ {
		got := isKeyChar(byte(i))
		want := ref[i]
		if got != want {
			t.Errorf("isKeyChar(%d / %q): got %v, want %v", i, rune(i), got, want)
		}
	}
}

func TestEscapeDetectionInFindValueEnd(t *testing.T) {
	// Verify that findValueEnd correctly handles escaped equals signs,
	// which exercises the inline escape-detection logic that replaced isEscapedAt.
	tests := []struct {
		name string
		data string
		want uint32
	}{
		{"unescaped_eq", "val key=x", 3},
		{"escaped_eq", "val\\= key=x", 5},
		{"double_backslash_eq", "val\\\\ key=x", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.data)
			got := findValueEnd(data, 0, safeU32(len(data)))
			if got != tt.want {
				t.Errorf("findValueEnd(%q, 0, %d) = %d, want %d",
					tt.data, len(data), got, tt.want)
			}
		})
	}
}

func TestValidKeyEmpty(t *testing.T) {
	if validKey(nil) {
		t.Error("expected false for nil key")
	}
	if validKey([]byte{}) {
		t.Error("expected false for empty key")
	}
}

func TestFindValueEndOutOfRange(t *testing.T) {
	// Exercise the guard: start >= end should return end.
	data := []byte("hello")
	got := findValueEnd(data, 100, 5)
	if got != 5 {
		t.Errorf("findValueEnd with start > end returned %d, want 5", got)
	}
	// start == end should also return end.
	got = findValueEnd(data, 5, 5)
	if got != 5 {
		t.Errorf("findValueEnd with start == end returned %d, want 5", got)
	}
}

func TestFindValueEnd(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		start uint32
		want  uint32
	}{
		{"no_equals", "hello", 0, 5},
		{"next_key", "hello key=val", 0, 5},
		{"trailing_spaces", "hello   ", 0, 5},
		{"escaped_equals", "hello\\=world", 0, 12},
		{"no_space_before_eq", "hello=world", 0, 11},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.data)
			got := findValueEnd(data, tt.start, safeU32(len(data)))
			if got != tt.want {
				t.Errorf("findValueEnd(%q, %d, %d) = %d, want %d",
					tt.data, tt.start, len(data), got, tt.want)
			}
		})
	}
}

func TestFindValueEndLongKeyRejected(t *testing.T) {
	m := NewParser()
	longKey := strings.Repeat("a", 64)
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=value ` + longKey + `=next`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "value "+longKey+"=next")
}

func TestFindValueEndNoMoreKeys(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|msg=just a value with no more keys`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "just a value with no more keys")
}

func TestFindValueEndNoValidKeyBoundary(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|msg=2+2=`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "2+2=")
}

func TestFindValueEndEscapedEqualsAtEnd(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=value\=`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", `value\=`)
}

func TestFindValueEndEqualsImmediatelyAfterValue(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg== src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "=")
	assertExt(t, e, "src", "1.2.3.4")
}

func TestFindValueEndDoSBudget(t *testing.T) {
	fakeEquals := strings.Repeat("@=", 2000)
	input := []byte("CEF:0|V|P|1|100|N|5|msg=" + fakeEquals)
	m := NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount != 1 {
		t.Errorf("ext count: got %d, want 1", e.ExtCount)
	}
	assertExt(t, e, "msg", strings.TrimRight(fakeEquals, " "))
}
