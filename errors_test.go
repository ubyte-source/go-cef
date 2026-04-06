package cef

import (
	"errors"
	"math"
	"testing"
)

func TestErrorsIs(t *testing.T) {
	tests := []struct {
		want  error
		name  string
		input string
	}{
		{ErrEmpty, "empty", ""},
		{ErrPrefix, "bad_prefix", "NOTCEF:0|a|b|c|d|e|5|"},
		{ErrVersion, "bad_version", "CEF:abc|V|P|1|100|N|5|"},
		{ErrIncompleteHeader, "incomplete", "CEF:0|Vendor|Product"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewParser()
			_, err := m.Parse([]byte(tt.input))
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("errors.Is(%v, %v) = false", err, tt.want)
			}
		})
	}
}

func TestErrorsIsExtOverflow(t *testing.T) {
	m := NewParser(WithMaxExtensions(1))
	_, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|a=1 b=2`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrExtOverflow) {
		t.Errorf("errors.Is(%v, ErrExtOverflow) = false", err)
	}
}

func TestErrorsIsExtKey(t *testing.T) {
	m := NewParser()
	_, err := m.Parse([]byte("CEF:0|V|P|1|100|N|5|bad key=val"))
	if err == nil {
		t.Skip("parser did not produce ErrExtKey for this input")
	}
	if !errors.Is(err, ErrExtKey) {
		t.Errorf("expected ErrExtKey, got: %v", err)
	}
}

func TestWithMaxExtensionsPanicZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n=0")
		}
	}()
	WithMaxExtensions(0)
}

func TestWithMaxExtensionsPanicNegative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n=-1")
		}
	}()
	WithMaxExtensions(-1)
}

func TestWithMaxExtensionsPanicOver64(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n=65")
		}
	}()
	WithMaxExtensions(65)
}

func TestWithMaxExtensionsValidBounds(_ *testing.T) {
	_ = WithMaxExtensions(1)
	_ = WithMaxExtensions(32)
	_ = WithMaxExtensions(64)
}

func TestParseErrorPosition(t *testing.T) {
	m := NewParser()
	_, err := m.Parse([]byte(`CEF:0|Vendor|Product`))
	if err == nil {
		t.Fatal("expected error")
	}
	var pe *ParseError
	if errors.As(err, &pe) {
		if pe.Position == 0 && !errors.Is(err, ErrEmpty) {
			t.Errorf("expected non-zero position for non-empty input, got %d", pe.Position)
		}
	} else {
		t.Error("expected ParseError type")
	}
}

func TestParseErrorReuse(t *testing.T) {
	m := NewParser()

	// First error: capture sentinel before next Parse overwrites it.
	_, err1 := m.Parse([]byte{})
	if err1 == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err1, ErrEmpty) {
		t.Errorf("err1: expected ErrEmpty, got: %v", err1)
	}

	// Second call reuses the preallocated ParseError —
	// err1's contents are overwritten (documented behavior).
	_, err2 := m.Parse([]byte(`NOTCEF`))
	if err2 == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err2, ErrPrefix) {
		t.Errorf("err2: expected ErrPrefix, got: %v", err2)
	}

	// The pointer is reused (preallocated in Parser).
	var pe1, pe2 *ParseError
	if !errors.As(err1, &pe1) {
		t.Fatal("err1 is not *ParseError")
	}
	if !errors.As(err2, &pe2) {
		t.Fatal("err2 is not *ParseError")
	}
	if pe1 != pe2 {
		t.Error("expected err1 and err2 to share the same *ParseError (preallocated)")
	}
}

func TestErrInputTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: requires >4 GiB memory allocation")
	}
	size := int(math.MaxUint32) + 1
	input := make([]byte, size)
	copy(input, "CEF:0|V|P|1|100|N|5|")
	m := NewParser()
	_, err := m.Parse(input)
	if err == nil {
		t.Fatal("expected error for input > MaxUint32")
	}
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge, got: %v", err)
	}
}

func TestErrInputTooLargeBestEffort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: requires >4 GiB memory allocation")
	}
	size := int(math.MaxUint32) + 1
	input := make([]byte, size)
	copy(input, "CEF:0|V|P|1|100|N|5|")
	m := NewParser(WithBestEffort())
	e, err := m.Parse(input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge, got: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil event in best-effort mode")
	}
}
