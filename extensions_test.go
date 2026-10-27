package cef

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// extPairs parses testHeaderOnly followed by ext under MaxExtensions and returns the
// pairs as key=value texts, with the error.
func extPairs(t *testing.T, ext string) ([]string, error) {
	t.Helper()
	var e Event
	err := e.Parse([]byte(testHeaderOnly+ext), MaxExtensions)
	pairs := make([]string, 0, e.ExtCount())
	for k, v := range e.All() {
		pairs = append(pairs, e.Text(k)+"="+e.Text(v))
	}
	if !e.HeaderComplete() {
		t.Fatalf("Parse of extension %q: HeaderComplete() = %t, want true", ext, e.HeaderComplete())
	}
	return pairs, err
}

func TestEventParseExtensionsReadsThePairs(t *testing.T) {
	for _, tc := range []struct {
		ext  string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"\r\n", nil},
		{"src=10.0.0.1", []string{"src=10.0.0.1"}},
		{"  src=1 dst=2", []string{"src=1", "dst=2"}},
		{"src= dst=1", []string{"src=", "dst=1"}},
		{"a=1  b=2", []string{"a=1 ", "b=2"}},
		{"a=1 b=2   ", []string{"a=1", "b=2"}},
		{"a=1 b=2\r\n", []string{"a=1", "b=2"}},
		{"a=1 b=2 \r \n", []string{"a=1", "b=2"}},
		{"msg=a b c=d", []string{"msg=a b", "c=d"}},
		{"url=http://x/?a=b&c=d e=f", []string{"url=http://x/?a=b&c=d", "e=f"}},
		{`msg=a \= b c=d`, []string{`msg=a \= b`, "c=d"}},
		{`msg=x \c=d`, []string{`msg=x \c=d`}},
		{"msg=x\tc=d", []string{"msg=x\tc=d"}},
		{"msg=x :c=d", []string{"msg=x :c=d"}},
		{"a==b", []string{"a==b"}},
		{"a==b c=d", []string{"a==b", "c=d"}},
		{"a=1 =2", []string{"a=1 =2"}},
		{"ad.x[0]=1 cs1-Label_x=2", []string{"ad.x[0]=1", "cs1-Label_x=2"}},
		{"k=" + strings.Repeat("ab=", 300) + " z=1", []string{"k=" + strings.Repeat("ab=", 300), "z=1"}},
		{"k=v " + strings.Repeat("a", 200) + "=x", []string{"k=v", strings.Repeat("a", 200) + "=x"}},
	} {
		got, err := extPairs(t, tc.ext)
		if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("extension %q = %q, %v, want %q, nil", tc.ext, got, err, tc.want)
		}
	}
}

func TestEventParseExtensionsKeyFaults(t *testing.T) {
	first := len(testHeaderOnly)
	for _, tc := range []struct {
		ext string
		pos int
	}{
		{"junk", first},
		{"  junk  ", first + 2},
		{"junk k=v", first},
		{"=v", first},
		{"bad key=v", first},
		{"k:x=v", first},
	} {
		var e Event
		err := e.Parse([]byte(testHeaderOnly+tc.ext), MaxExtensions)
		if pe := asParseError(err); pe == nil || !errors.Is(err, ErrExtKey) || int(pe.Position) != tc.pos {
			t.Errorf("extension %q = %v, want ErrExtKey at byte %d", tc.ext, err, tc.pos)
		}
		if !e.HeaderComplete() || e.ExtCount() != 0 || e.Text(e.Name()) != "Name" {
			t.Errorf("extension %q: HeaderComplete %t, ExtCount %d, Name %q, want the header kept and no pair",
				tc.ext, e.HeaderComplete(), e.ExtCount(), e.Text(e.Name()))
		}
	}
}

func TestEventParseExtensionsOverflowKeepsThePairsBefore(t *testing.T) {
	var e Event
	line := []byte(testHeaderOnly + "a=1 b=2 c=3")
	err := e.Parse(line, 2)
	if pe := asParseError(err); pe == nil || !errors.Is(err, ErrExtOverflow) || int(pe.Position) != len(line)-3 {
		t.Fatalf("Parse(%q, 2) = %v, want ErrExtOverflow at byte %d", line, err, len(line)-3)
	}
	if p, ok := e.ExtAt(1); !ok || e.Text(p.Value) != "2" || e.ExtCount() != 2 {
		t.Errorf("Parse(%q, 2): pairs %d, second value %q, want 2 pairs ending with 2",
			line, e.ExtCount(), e.Bytes(p.Value))
	}
}

func TestClassStartFindsTheRunOfItsClass(t *testing.T) {
	for _, tc := range []struct {
		b     string
		class byte
		want  int
	}{
		{"", classTrailing, 0},
		{"a", classTrailing, 1},
		{"a \r\n", classTrailing, 1},
		{" \r\n", classTrailing, 0},
		{"a\tb\t", classTrailing, 4},
		{"a\\ ", classTrailing, 2},
		{"", classKey, 0},
		{"abc", classKey, 0},
		{"x dst", classKey, 2},
		{"x=abc", classKey, 2},
		{"x a:b", classKey, 4},
		{"x ", classKey, 2},
	} {
		if got := classStart([]byte(tc.b), tc.class); got != tc.want {
			t.Errorf("classStart(%q, %#x) = %d, want %d", tc.b, tc.class, got, tc.want)
		}
	}
}

func TestValueEndFindsTheNextKey(t *testing.T) {
	for _, tc := range []struct {
		ext       string
		from      int
		end, next int
	}{
		{"k=v", 2, 3, -1},
		{"k=v x=y", 2, 3, 5},
		{"k= x=y", 2, 2, 4},
		{"k=a=b c=d", 2, 5, 7},
		{"k=a :b=c", 2, 8, -1},
		{"k==v x=y", 2, 4, 6},
		{"k=a =b", 2, 6, -1},
	} {
		end, next := valueEnd([]byte(tc.ext), tc.from)
		if end != tc.end || next != tc.next {
			t.Errorf("valueEnd(%q, %d) = %d, %d, want %d, %d", tc.ext, tc.from, end, next, tc.end, tc.next)
		}
	}
}

func TestEventGrowPairsFirstTakesTheStartOrALowerLimit(t *testing.T) {
	for limit, want := range map[int]int{1: 1, 15: 15, 16: 16, 17: 16} {
		var e Event
		e.growPairs(limit)
		if cap(e.pairs) != want {
			t.Errorf("first growth under the limit %d = %d pairs, want %d", limit, cap(e.pairs), want)
		}
	}
}

func TestEventGrowPairsDoublesUpToTheLimit(t *testing.T) {
	var e Event
	caps := make([]int, 0, 5)
	for range 5 {
		e.growPairs(100)
		caps = append(caps, cap(e.pairs))
	}
	if want := []int{16, 32, 64, 100, 100}; !slices.Equal(caps, want) {
		t.Errorf("pair storage after each growth = %v, want %v", caps, want)
	}
	if got := reflect.TypeFor[pair]().Size(); got != 16 {
		t.Errorf("pair record = %d bytes, want 16", got)
	}
}
