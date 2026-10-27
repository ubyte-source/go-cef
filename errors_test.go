package cef

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// sentinels returns every sentinel of the package with its documented text.
func sentinels() []struct {
	err  error
	text string
} {
	return []struct {
		err  error
		text string
	}{
		{ErrEmpty, "cef: empty input"},
		{ErrPrefix, "cef: expecting CEF: prefix"},
		{ErrVersion, "cef: version is not 1 to 4 digits without a leading zero"},
		{ErrIncompleteHeader, "cef: incomplete CEF header"},
		{ErrExtKey, "cef: invalid extension key"},
		{ErrExtOverflow, "cef: extension count exceeds maximum"},
		{ErrInputTooLarge, "cef: input longer than 4294967295 bytes"},
		{ErrInvalidUTF8, "cef: event text is not UTF-8"},
	}
}

func TestConstErrorErrorTexts(t *testing.T) {
	for _, s := range sentinels() {
		if got := s.err.Error(); got != s.text {
			t.Errorf("sentinel text = %q, want %q", got, s.text)
		}
	}
}

func TestParseErrorErrorNamesTheOffset(t *testing.T) {
	for _, tc := range []struct {
		pos  uint32
		want string
	}{
		{0, "cef: incomplete CEF header at byte 0"},
		{19, "cef: incomplete CEF header at byte 19"},
		{4294967295, "cef: incomplete CEF header at byte 4294967295"},
	} {
		pe := &ParseError{Err: ErrIncompleteHeader, Position: tc.pos}
		if got := pe.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

func TestParseErrorUnwrapMatchesTheSentinel(t *testing.T) {
	for _, s := range sentinels() {
		var err error = &ParseError{Err: s.err, Position: 7}
		if !errors.Is(err, s.err) {
			t.Errorf("errors.Is(ParseError{%v}, %v) = false, want true", s.err, s.err)
		}
		if got := errors.Unwrap(err); !errors.Is(got, s.err) || errors.Unwrap(got) != nil {
			t.Errorf("Unwrap() = %v, want %v", got, s.err)
		}
		for _, other := range sentinels() {
			if other.text != s.text && errors.Is(err, other.err) {
				t.Errorf("errors.Is(ParseError{%v}, %v) = true, want false", s.err, other.err)
			}
		}
	}
}

func TestParseErrorAllocs(t *testing.T) {
	pe := &ParseError{Err: ErrExtKey, Position: 4294967295}
	var text string
	var err error
	assertAllocs(t, 1, func() { text = pe.Error() })
	assertAllocs(t, 0, func() { err = pe.Unwrap() })
	if text != "cef: invalid extension key at byte 4294967295" || !errors.Is(err, ErrExtKey) {
		t.Errorf("Error() = %q, Unwrap() = %v, want the text and ErrExtKey", text, err)
	}
}

func TestFaultIsFreshPerCall(t *testing.T) {
	a, b := fault(3, ErrExtKey), fault(3, ErrExtKey)
	pa, pb := asParseError(a), asParseError(b)
	if pa == nil || pb == nil || pa == pb {
		t.Fatalf("fault(3, ErrExtKey) twice = %p and %p, want a fresh *ParseError per call", pa, pb)
	}
	if pa.Position != 3 || !errors.Is(a, ErrExtKey) {
		t.Errorf("fault(3, ErrExtKey) = %v, want ErrExtKey at byte 3", a)
	}
}

func FuzzParseErrorError(f *testing.F) {
	f.Add(uint32(0), 0)
	f.Add(uint32(4294967295), 7)
	f.Fuzz(func(t *testing.T, pos uint32, which int) {
		all := sentinels()
		s := all[uint(which)%uint(len(all))]
		pe := &ParseError{Err: s.err, Position: pos}
		want := s.text + " at byte " + strconv.FormatUint(uint64(pos), 10)
		if got := pe.Error(); got != want {
			t.Fatalf("Error() = %q, want %q", got, want)
		}
		if !errors.Is(pe, s.err) || !errors.Is(pe.Unwrap(), s.err) {
			t.Fatalf("ParseError{%v}: Is = %t, Unwrap() = %v, want true and %v", s.err, errors.Is(pe, s.err),
				pe.Unwrap(), s.err)
		}
		if !strings.HasPrefix(pe.Error(), "cef: ") {
			t.Fatalf("Error() = %q, want the prefix %q", pe.Error(), "cef: ")
		}
	})
}

func BenchmarkParseErrorError(b *testing.B) {
	pe := &ParseError{Err: ErrIncompleteHeader, Position: 19}
	if got := pe.Error(); got != "cef: incomplete CEF header at byte 19" {
		b.Fatalf("Error() = %q, want the documented text", got)
	}
	out := heapCell[string](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = pe.Error()
	}
}

func BenchmarkParseErrorUnwrap(b *testing.B) {
	pe := &ParseError{Err: ErrIncompleteHeader, Position: 19}
	if !errors.Is(pe.Unwrap(), ErrIncompleteHeader) {
		b.Fatalf("Unwrap() = %v, want %v", pe.Unwrap(), ErrIncompleteHeader)
	}
	out := heapCell[error](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = pe.Unwrap()
	}
}

func BenchmarkConstErrorError(b *testing.B) {
	if ErrEmpty.Error() != "cef: empty input" {
		b.Fatalf("ErrEmpty.Error() = %q, want %q", ErrEmpty.Error(), "cef: empty input")
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = ErrEmpty.Error()
	}
}

func ExampleParseError() {
	var e Event
	err := e.Parse([]byte("CEF:0|Vendor|Product"), MaxExtensions)
	fmt.Println(err, errors.Is(err, ErrIncompleteHeader))
	// Output: cef: incomplete CEF header at byte 20 true
}
