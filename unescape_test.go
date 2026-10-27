package cef

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Fixtures of the unescape tests: a trailing backslash, unknown escapes and a pipe that
// no backslash escapes.
const (
	testBackslashTrailing   = `test\`
	testHeaderUnknownEscape = `test\n kept`
	testExtUnknownEscape    = `test\x kept`
	testPipeNotEscaped      = "contains | pipe"
)

// refUnescape decodes each escape pair of table left to right and keeps any other
// backslash as a literal byte.
func refUnescape(raw []byte, table map[byte]byte) []byte {
	out := []byte{}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			if r, ok := table[raw[i+1]]; ok {
				out = append(out, r)
				i++
				continue
			}
		}
		out = append(out, raw[i])
	}
	return out
}

// Escape tables of the reference: the byte after a backslash and the byte the pair
// stands for.
func refHeaderEscapes() map[byte]byte { return map[byte]byte{'|': '|', '\\': '\\'} }

func refValueEscapes() map[byte]byte {
	return map[byte]byte{'=': '=', '\\': '\\', 'n': '\n', 'r': '\r'}
}

func TestUnescapeHeaderDecodes(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{testMsgHelloWorld, testMsgHelloWorld},
		{`a\|b`, "a|b"},
		{`a\\b`, `a\b`},
		{`\\\|`, `\|`},
		{testHeaderUnknownEscape, testHeaderUnknownEscape},
		{testBackslashTrailing, testBackslashTrailing},
		{testPipeNotEscaped, testPipeNotEscaped},
		{`a\=b`, `a\=b`},
	} {
		if got := UnescapeHeader([]byte(tc.raw), nil); string(got) != tc.want {
			t.Errorf("UnescapeHeader(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestUnescapeExtValueDecodes(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{testMsgHelloWorld, testMsgHelloWorld},
		{`a\=b`, "a=b"},
		{`a\\b`, `a\b`},
		{`line\nnext\r`, "line\nnext\r"},
		{testExtUnknownEscape, testExtUnknownEscape},
		{testBackslashTrailing, testBackslashTrailing},
		{`a\|b`, `a\|b`},
		{`\\\\\=`, `\\=`},
	} {
		if got := UnescapeExtValue([]byte(tc.raw), nil); string(got) != tc.want {
			t.Errorf("UnescapeExtValue(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestUnescapeCleanRawIsACappedView(t *testing.T) {
	buf := []byte("clean value and more")
	raw := buf[:11]
	for name, f := range map[string]func(raw, dst []byte) []byte{
		"UnescapeHeader": UnescapeHeader, "UnescapeExtValue": UnescapeExtValue,
	} {
		got := f(raw, nil)
		if &got[0] != &raw[0] || len(got) != 11 || cap(got) != 11 {
			t.Errorf("%s(%q) = len %d cap %d, want raw itself with capacity 11", name, raw, len(got), cap(got))
		}
		_ = append(got, 'X')
		if string(buf) != "clean value and more" {
			t.Errorf("%s: input after an append to the view = %q, want %q", name, buf, "clean value and more")
		}
	}
}

func TestUnescapeDecodesInPlace(t *testing.T) {
	for name, f := range map[string]func(raw, dst []byte) []byte{
		"UnescapeHeader": UnescapeHeader, "UnescapeExtValue": UnescapeExtValue,
	} {
		raw := []byte(`a\\b\|c\=d\ne`)
		want := string(f(bytes.Clone(raw), nil))
		if got := f(raw, raw[:0]); string(got) != want || &got[0] != &raw[0] {
			t.Errorf("%s in place = %q, want %q over the input", name, got, want)
		}
	}
}

func TestUnescapeGrowsDst(t *testing.T) {
	raw := []byte(`x\=` + strings.Repeat("y", 100))
	held := []byte("abcd")
	got := UnescapeExtValue(raw, held[:0])
	if string(got) != "x="+strings.Repeat("y", 100) {
		t.Fatalf("UnescapeExtValue = %q, want the decoded value", got)
	}
	if cap(got) < len(raw) || string(held) != "abcd" {
		t.Errorf("UnescapeExtValue into 4 bytes = capacity %d, dst %q, want room for %d and dst kept",
			cap(got), held, len(raw))
	}
}

func TestUnescapeAllocs(t *testing.T) {
	clean := []byte(testMsgHelloWorld)
	escaped := []byte(`a\=b\\c\nd`)
	dst := make([]byte, 0, 64)
	assertAllocs(t, 0, func() { _ = UnescapeHeader(clean, nil) })
	assertAllocs(t, 0, func() { _ = UnescapeExtValue(clean, nil) })
	assertAllocs(t, 0, func() { _ = UnescapeHeader(escaped, dst) })
	assertAllocs(t, 0, func() { _ = UnescapeExtValue(escaped, dst) })
	assertAllocs(t, 1, func() { _ = UnescapeExtValue(escaped, nil) })
	assertAllocs(t, 1, func() { _ = UnescapeHeader(escaped, nil) })
}

func TestUnescapeHeaderCostIsLinear(t *testing.T) {
	assertDecodeCost(t, "UnescapeHeader", UnescapeHeader, []string{`\\`, `\x`, `\|a`, "plain"})
}

func TestUnescapeExtValueCostIsLinear(t *testing.T) {
	assertDecodeCost(t, "UnescapeExtValue", UnescapeExtValue, []string{`\\`, `\x`, `\=a`, "plain"})
}

// assertDecodeCost fails t unless decode, named name, reads 4096 and 4096*costScale
// copies of each of units at a cost linear in their length.
func assertDecodeCost(t *testing.T, name string, decode func(raw, dst []byte) []byte, units []string) {
	t.Helper()
	for _, unit := range units {
		small, large := []byte(strings.Repeat(unit, 4096)), []byte(strings.Repeat(unit, 4096*costScale))
		dst := make([]byte, 0, len(large))
		var out []byte
		assertCost(t, func() { out = decode(small, dst) }, func() { out = decode(large, dst) }, costScale)
		if len(out) == 0 || t.Failed() {
			t.Fatalf("%s(%d x %q) = %d bytes, failed %t, want some and a linear cost",
				name, 4096*costScale, unit, len(out), t.Failed())
		}
	}
}

func TestUnescapedResolvesEscapeBytes(t *testing.T) {
	for c, want := range map[byte]byte{'n': '\n', 'r': '\r', '=': '=', '\\': '\\', '|': '|'} {
		if got := unescaped(c); got != want {
			t.Errorf("unescaped(%q) = %q, want %q", c, got, want)
		}
	}
}

func FuzzUnescapeHeader(f *testing.F) {
	for _, s := range []string{testMsgHelloWorld, `a\|b\\c`, testBackslashTrailing, `\\\\\|`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkUnescape(t, "UnescapeHeader", UnescapeHeader, raw, refHeaderEscapes())
	})
}

func FuzzUnescapeExtValue(f *testing.F) {
	for _, s := range []string{testMsgHelloWorld, `a\=b\\c\n\r`, testBackslashTrailing, testExtUnknownEscape} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkUnescape(t, "UnescapeExtValue", UnescapeExtValue, raw, refValueEscapes())
	})
}

// checkUnescape checks f against the reference on raw: out of place, in place and the
// capped view of clean input.
func checkUnescape(t *testing.T, name string, f func(raw, dst []byte) []byte, raw []byte, table map[byte]byte) {
	t.Helper()
	want := refUnescape(raw, table)
	got := f(raw, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s(%q) = %q, want %q", name, raw, got, want)
	}
	if bytes.IndexByte(raw, '\\') < 0 && (len(got) != len(raw) || cap(got) != len(raw)) {
		t.Fatalf("%s(%q) of clean input = len %d cap %d, want raw capped", name, raw, len(got), cap(got))
	}
	inPlace := bytes.Clone(raw)
	if got := f(inPlace, inPlace[:0]); !bytes.Equal(got, want) {
		t.Fatalf("%s(%q) in place = %q, want %q", name, raw, got, want)
	}
}

func BenchmarkUnescapeHeader(b *testing.B) {
	benchUnescape(b, UnescapeHeader, refHeaderEscapes())
}

func BenchmarkUnescapeExtValue(b *testing.B) {
	benchUnescape(b, UnescapeExtValue, refValueEscapes())
}

// benchUnescape measures f on a clean value, a typical escaped one and dense escapes.
func benchUnescape(b *testing.B, f func(raw, dst []byte) []byte, table map[byte]byte) {
	b.Helper()
	for _, s := range []struct {
		name string
		raw  []byte
	}{
		{"Clean", []byte("Suspicious network activity detected on OT segment")},
		{"Typical", []byte(`test\=value\nwith escapes and a \\ backslash \| pipe`)},
		{"Dense", []byte(strings.Repeat(`\\`, 512))},
	} {
		b.Run(s.name, func(b *testing.B) {
			dst := make([]byte, 0, len(s.raw))
			if got := f(s.raw, dst); !bytes.Equal(got, refUnescape(s.raw, table)) {
				b.Fatalf("unescape(%q) = %q, want the reference", s.raw, got)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(s.raw)))
			for b.Loop() {
				_ = f(s.raw, dst)
			}
		})
	}
}

func ExampleUnescapeHeader() {
	fmt.Println(string(UnescapeHeader([]byte(`detected a \| in message`), nil)))
	// Output: detected a | in message
}

func ExampleUnescapeExtValue() {
	fmt.Printf("%q\n", UnescapeExtValue([]byte(`a\=b\nc`), nil))
	// Output: "a=b\nc"
}
