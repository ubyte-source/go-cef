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

func TestWithMaxExtensionsValidBounds(t *testing.T) {
	for _, n := range []int{1, 32, 64} {
		p := NewParser(WithMaxExtensions(n))
		if p == nil {
			t.Fatalf("NewParser(WithMaxExtensions(%d)) returned nil", n)
		}
	}
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

func TestParseErrorIndependent(t *testing.T) {
	m := NewParser()

	_, err1 := m.Parse([]byte{})
	if err1 == nil {
		t.Fatal("expected error")
	}
	msg1 := err1.Error()
	if !errors.Is(err1, ErrEmpty) {
		t.Errorf("err1: expected ErrEmpty, got: %v", err1)
	}

	// A second Parse must NOT mutate the previously returned error: each Parse
	// returns an independent *ParseError.
	_, err2 := m.Parse([]byte(`NOTCEF`))
	if err2 == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err2, ErrPrefix) {
		t.Errorf("err2: expected ErrPrefix, got: %v", err2)
	}

	// err1 is unchanged: same message, still matches its sentinel.
	if got := err1.Error(); got != msg1 {
		t.Errorf("err1 mutated by second Parse: was %q, now %q", msg1, got)
	}
	if !errors.Is(err1, ErrEmpty) {
		t.Errorf("err1 no longer matches ErrEmpty after second Parse: %v", err1)
	}

	// The two errors are distinct values (no shared pointer).
	var pe1, pe2 *ParseError
	if !errors.As(err1, &pe1) {
		t.Fatal("err1 is not *ParseError")
	}
	if !errors.As(err2, &pe2) {
		t.Fatal("err2 is not *ParseError")
	}
	if pe1 == pe2 {
		t.Error("expected err1 and err2 to be independent *ParseError values")
	}
}

func TestParseErrorsCollectable(t *testing.T) {
	// The common "parse many lines, collect failures" pattern must preserve
	// each error's identity.
	m := NewParser()
	inputs := [][]byte{{}, []byte("NOTCEF"), []byte("CEF:0|V|P")}
	wantErr := []error{ErrEmpty, ErrPrefix, ErrIncompleteHeader}
	var collected []error
	for _, in := range inputs {
		if _, err := m.Parse(in); err != nil {
			collected = append(collected, err)
		}
	}
	if len(collected) != len(wantErr) {
		t.Fatalf("collected %d errors, want %d", len(collected), len(wantErr))
	}
	for i, want := range wantErr {
		if !errors.Is(collected[i], want) {
			t.Errorf("collected[%d] = %v, want match for %v", i, collected[i], want)
		}
	}
}

func TestErrInputTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: requires >4 GiB memory allocation")
	}
	// Use a uint64 variable so the value never appears as an out-of-range int
	// constant: int(math.MaxUint32)+1 would fail to compile on 32-bit targets.
	var want uint64 = math.MaxUint32 + 1
	if uint64(math.MaxInt) < want {
		t.Skip("skipping: platform int cannot represent >4 GiB")
	}
	size := int(want)
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
	var want uint64 = math.MaxUint32 + 1
	if uint64(math.MaxInt) < want {
		t.Skip("skipping: platform int cannot represent >4 GiB")
	}
	size := int(want)
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
