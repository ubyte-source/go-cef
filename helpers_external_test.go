package cef_test

// assertSpan and assertExt are duplicated in cef_test.go (package cef).
// Go requires separate helpers for internal and external test packages.
// This is the standard Go pattern — do not refactor into a shared file.

import (
	"testing"

	cef "github.com/ubyte-source/go-cef"
)

func assertSpan(t *testing.T, e *cef.Event, s cef.Span, want string) {
	t.Helper()
	got := e.Text(s)
	if got != want {
		t.Errorf("span: got %q, want %q", got, want)
	}
}

func assertExt(t *testing.T, e *cef.Event, key, want string) {
	t.Helper()
	span, ok := e.ExtString(key)
	if !ok {
		t.Fatalf("extension %q not found (extCount=%d)", key, e.ExtCount)
	}
	got := e.Text(span)
	if got != want {
		t.Errorf("ext %q: got %q, want %q", key, got, want)
	}
}
