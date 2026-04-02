package cef

import "testing"

// assertSpan and assertExt are shared test helpers for internal test files
// (package cef). External test files (package cef_test) have their own copy
// in helpers_external_test.go — this duplication is required by Go's test
// package model.

func assertSpan(t *testing.T, e *Event, s Span, want string) {
	t.Helper()
	got := e.Text(s)
	if got != want {
		t.Errorf("span: got %q, want %q", got, want)
	}
}

func assertExt(t *testing.T, e *Event, key, want string) {
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
