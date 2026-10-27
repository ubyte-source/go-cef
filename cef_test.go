package cef

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// testEvent is the event most cef.go tests read.
const testEvent = `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|` +
	`src=10.0.0.1 dst=2.1.2.2 spt=1232 msg=a \= b`

// parsed returns an Event parsed from line, failing t on a fault.
func parsed(tb testing.TB, line string) *Event {
	tb.Helper()
	e := new(Event)
	if err := e.Parse([]byte(line), MaxExtensions); err != nil {
		tb.Fatalf("Parse(%q) = %v, want nil", line, err)
	}
	return e
}

// fields returns the bytes of every header field and pair of e, with its version,
// HeaderComplete and pair count, as one comparable text.
func fields(e *Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "v%d headerComplete=%t n=%d", e.Version(), e.HeaderComplete(), e.ExtCount())
	header := [...]Span{e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(),
		e.Name(), e.Severity()}
	for _, s := range header {
		fmt.Fprintf(&b, "|%q", e.Bytes(s))
	}
	for k, v := range e.All() {
		fmt.Fprintf(&b, " %q=%q", e.Bytes(k), e.Bytes(v))
	}
	return b.String()
}

func TestVersionStringIsDecimal(t *testing.T) {
	for _, v := range []Version{0, 1, 9, 10, 99, 100, 9999, -1} {
		if got, want := v.String(), strconv.Itoa(int(v)); got != want {
			t.Errorf("Version(%d).String() = %q, want %q", int(v), got, want)
		}
	}
	assertAllocs(t, 0, func() { _ = Version(99).String() })
	assertAllocs(t, 1, func() { _ = Version(100).String() })
}

func TestSpanLenAndIsEmpty(t *testing.T) {
	for _, tc := range []struct {
		s     Span
		len   uint32
		empty bool
	}{
		{Span{Start: 2, End: 5}, 3, false},
		{Span{Start: 4, End: 5}, 1, false},
		{Span{Start: 5, End: 5}, 0, true},
		{Span{}, 0, true},
		{Span{Start: 6, End: 5}, 0, true},
		{Span{Start: math.MaxUint32, End: 7}, 0, true},
		{Span{Start: 0, End: math.MaxUint32}, math.MaxUint32, false},
	} {
		if got := tc.s.Len(); got != tc.len {
			t.Errorf("%v.Len() = %d, want %d", tc.s, got, tc.len)
		}
		if got := tc.s.IsEmpty(); got != tc.empty {
			t.Errorf("%v.IsEmpty() = %t, want %t", tc.s, got, tc.empty)
		}
	}
}

func TestSpanAndExtPairString(t *testing.T) {
	s := Span{Start: 4294967295, End: 7}
	if got := s.String(); got != "[4294967295:7]" {
		t.Errorf("Span.String() = %q, want %q", got, "[4294967295:7]")
	}
	p := ExtPair{Key: Span{Start: 1, End: 4}, Value: Span{Start: 5, End: 4294967295}}
	if got := p.String(); got != "[1:4]=[5:4294967295]" {
		t.Errorf("ExtPair.String() = %q, want %q", got, "[1:4]=[5:4294967295]")
	}
	widest := Span{Start: math.MaxUint32, End: math.MaxUint32}
	longest := ExtPair{Key: widest, Value: widest}
	if got, want := longest.String(), "[4294967295:4294967295]=[4294967295:4294967295]"; got != want {
		t.Errorf("ExtPair.String() = %q, want %q", got, want)
	}
	var text string
	assertAllocs(t, 1, func() { text = s.String() })
	assertAllocs(t, 1, func() { text = p.String() })
	assertAllocs(t, 1, func() { text = widest.String() })
	assertAllocs(t, 1, func() { text = longest.String() })
	_ = text
	assertAllocs(t, 0, func() { _ = s.Len() })
	assertAllocs(t, 0, func() { _ = s.IsEmpty() })
}

func TestEventAccessorsReadTheHeader(t *testing.T) {
	e := parsed(t, testEvent)
	for _, tc := range []struct {
		name string
		got  Span
		want string
	}{
		{"DeviceVendor", e.DeviceVendor(), "Security"},
		{"DeviceProduct", e.DeviceProduct(), "threatmanager"},
		{"DeviceVersion", e.DeviceVersion(), "1.0"},
		{"DeviceEventClassID", e.DeviceEventClassID(), "100"},
		{"Name", e.Name(), "worm successfully stopped"},
		{"Severity", e.Severity(), "10"},
	} {
		if got := e.Text(tc.got); got != tc.want {
			t.Errorf("%s() = %q, want %q", tc.name, got, tc.want)
		}
	}
	if e.Version() != 0 || !e.HeaderComplete() || e.ExtCount() != 4 {
		t.Errorf("Version(), HeaderComplete(), ExtCount() = %d, %t, %d, want 0, true, 4", e.Version(),
			e.HeaderComplete(), e.ExtCount())
	}
	assertAllocs(t, 0, func() {
		_, _, _, _, _ = e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(), e.Name()
		_, _, _, _ = e.Severity(), e.Version(), e.HeaderComplete(), e.ExtCount()
	})
}

func TestEventZeroValueIsEmpty(t *testing.T) {
	var e Event
	if got, want := fields(&e), `v0 headerComplete=false n=0|""|""|""|""|""|""`; got != want {
		t.Errorf("fields of the zero Event = %s, want %s", got, want)
	}
	if s, ok := e.ExtString("src"); ok {
		t.Errorf("ExtString(src) on the zero Event = %v, %t, want false", s, ok)
	}
	for _, s := range []Span{{}, {Start: 0, End: 1}} {
		if b := e.Bytes(s); b == nil || len(b) != 0 || cap(b) != 0 {
			t.Errorf("Bytes(%v) on the zero Event = %q cap %d (nil %t), want an empty view", s, b, cap(b), b == nil)
		}
	}
}

// testEventPairs are the pairs of testEvent in input order.
func testEventPairs() []string {
	return []string{"src=10.0.0.1", "dst=2.1.2.2", "spt=1232", `msg=a \= b`}
}

func TestEventExtAtFollowsTheInput(t *testing.T) {
	e := parsed(t, testEvent)
	for i, want := range testEventPairs() {
		if p, ok := e.ExtAt(i); !ok || e.Text(p.Key)+"="+e.Text(p.Value) != want {
			t.Errorf("ExtAt(%d) = %q=%q, %t, want %q", i, e.Bytes(p.Key), e.Bytes(p.Value), ok, want)
		}
	}
	for _, i := range []int{-1, 4, math.MaxInt} {
		if p, ok := e.ExtAt(i); ok || p != (ExtPair{}) {
			t.Errorf("ExtAt(%d) = %v, %t, want the zero pair and false", i, p, ok)
		}
	}
	var p ExtPair
	assertAllocs(t, 0, func() { p, _ = e.ExtAt(3) })
	if e.Text(p.Key) != "msg" {
		t.Errorf("ExtAt(3) key = %q, want msg", e.Bytes(p.Key))
	}
}

func TestEventAllFollowsTheInputAndStops(t *testing.T) {
	e := parsed(t, testEvent)
	want := testEventPairs()
	var got []string
	for k, v := range e.All() {
		got = append(got, e.Text(k)+"="+e.Text(v))
		if len(got) == 2 {
			break
		}
	}
	if strings.Join(got, " ") != strings.Join(want[:2], " ") {
		t.Errorf("All() until the second pair = %q, want %q", got, want[:2])
	}
	n := 0
	assertAllocs(t, 0, func() {
		n = 0
		for range e.All() {
			n++
		}
	})
	if n != len(want) {
		t.Errorf("pairs of All() = %d, want %d", n, len(want))
	}
}

func TestEventExtReturnsTheLastDuplicate(t *testing.T) {
	e := parsed(t, testHeaderOnly+"dvchost=first src=1 dvchost=last")
	for _, got := range []func() (Span, bool){
		func() (Span, bool) { return e.ExtString("dvchost") },
		func() (Span, bool) { return e.Ext([]byte("dvchost")) },
	} {
		if s, ok := got(); !ok || e.Text(s) != "last" {
			t.Errorf("lookup of a repeated key = %q, %t, want %q", e.Bytes(s), ok, "last")
		}
	}
}

func TestEventExtComparesTheWholeKey(t *testing.T) {
	e := parsed(t, testHeaderOnly+"abc=3 abcd=4 abcde=5 abcdf=6 x=1")
	for _, tc := range []struct {
		key   string
		value string
		ok    bool
	}{
		{"abc", "3", true},
		{"abcd", "4", true},
		{"abcde", "5", true},
		{"abcdf", "6", true},
		{"x", "1", true},
		{"abcdg", "", false},
		{"abc\x00", "", false},
		{"ab", "", false},
		{"", "", false},
		{"abcdef", "", false},
		{"Xbcd", "", false},
		{"ebcd", "", false},
		{"aXcd", "", false},
		{"abXd", "", false},
		{"abcX", "", false},
		{"Xbcde", "", false},
		{"Xbc", "", false},
		{"aXc", "", false},
		{"abX", "", false},
		{"y", "", false},
	} {
		s, ok := e.ExtString(tc.key)
		if ok != tc.ok || e.Text(s) != tc.value {
			t.Errorf("ExtString(%q) = %q, %t, want %q, %t", tc.key, e.Bytes(s), ok, tc.value, tc.ok)
		}
		if bs, bok := e.Ext([]byte(tc.key)); bs != s || bok != ok {
			t.Errorf("Ext(%q) = %v, %t, want ExtString's %v, %t", tc.key, bs, bok, s, ok)
		}
	}
	assertAllocs(t, 0, func() { _, _ = e.ExtString("abcde") })
	key := []byte("abcdf")
	assertAllocs(t, 0, func() { _, _ = e.Ext(key) })
}

func TestEventBytesReadsOnlyItsBytes(t *testing.T) {
	e := parsed(t, testHeaderOnly)
	n := uint32(len(testHeaderOnly))
	for _, tc := range []struct {
		s    Span
		want string
	}{
		{Span{Start: 0, End: 4}, "CEF:"},
		{Span{Start: n - 2, End: n}, "5|"},
		{Span{Start: n, End: n}, ""},
		{Span{Start: 3, End: 2}, ""},
		{Span{Start: 1, End: 0}, ""},
		{Span{Start: 0, End: n + 1}, ""},
		{Span{Start: 0, End: 1 << 31}, ""},
		{Span{Start: 1 << 31, End: 1<<31 + 1}, ""},
		{Span{Start: math.MaxUint32, End: math.MaxUint32}, ""},
	} {
		got := e.Bytes(tc.s)
		if got == nil || string(got) != tc.want || cap(got) != len(tc.want) {
			t.Errorf("Bytes(%v) = %q cap %d (nil %t), want %q cap %d", tc.s, got, cap(got), got == nil,
				tc.want, len(tc.want))
		}
		if text := e.Text(tc.s); text != tc.want {
			t.Errorf("Text(%v) = %q, want %q", tc.s, text, tc.want)
		}
		if b := e.AppendBytes([]byte("x"), tc.s); string(b) != "x"+tc.want {
			t.Errorf("AppendBytes(x, %v) = %q, want %q", tc.s, b, "x"+tc.want)
		}
	}
	prefix := e.Bytes(Span{Start: 0, End: 4})
	_ = append(prefix, '!')
	if got := string(e.Bytes(Span{Start: 0, End: 5})); got != "CEF:0" {
		t.Errorf("Bytes([0:5]) after an append to Bytes([0:4]) = %q, want %q", got, "CEF:0")
	}
	dst := make([]byte, 0, 64)
	assertAllocs(t, 0, func() { _ = e.Bytes(Span{Start: 6, End: 12}) })
	var text string
	assertAllocs(t, 1, func() { text = e.Text(Span{Start: 6, End: 12}) })
	assertAllocs(t, 1, func() { text = e.Text(Span{Start: 6, End: 8}) })
	assertAllocs(t, 0, func() { text = e.Text(Span{Start: 6, End: 7}) })
	assertAllocs(t, 0, func() { text = e.Text(Span{Start: 6, End: 6}) })
	_ = text
	assertAllocs(t, 0, func() { _ = e.AppendBytes(dst, Span{Start: 6, End: 12}) })
}

func TestEventCloneOwnsItsBytes(t *testing.T) {
	input := []byte(testEvent)
	var e Event
	if err := e.Parse(input, MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	want := fields(&e)
	c := e.Clone()
	for i := range input {
		input[i] = 'X'
	}
	if got := fields(c); got != want {
		t.Errorf("Clone after the input changed = %s, want %s", got, want)
	}
	const end = uint32(len(testEvent) - len("CEF:0|"))
	if got, covered := c.Bytes(Span{End: end}), testEvent[len("CEF:0|"):]; string(got) != covered {
		t.Errorf("bytes of the Clone = %q, want %q", got, covered)
	}
	if got := c.Bytes(Span{End: end + 1}); got == nil || len(got) != 0 || cap(got) != 0 {
		t.Errorf("Clone: Bytes past the covered bytes = %q cap %d (nil %t), want an empty view", got, cap(got),
			got == nil)
	}
}

func TestEventCloneRebasesTheSpans(t *testing.T) {
	e := parsed(t, "CEF:0||P|1|C|N|5|k=v")
	c := e.Clone()
	got := [...]Span{c.DeviceVendor(), c.DeviceProduct(), c.DeviceVersion(), c.DeviceEventClassID(), c.Name(),
		c.Severity()}
	want := [...]Span{{0, 0}, {1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}}
	if got != want {
		t.Errorf("Clone header spans = %v, want %v", got, want)
	}
	if p, ok := c.ExtAt(0); !ok || p != (ExtPair{Key: Span{11, 12}, Value: Span{13, 14}}) {
		t.Errorf("Clone ExtAt(0) = %v, %t, want [11:12]=[13:14]", p, ok)
	}
}

func TestEventCloneToWritesOnlyDst(t *testing.T) {
	a, b := []byte(testEvent), []byte(testHeaderOnly+"k=v")
	var e, dst Event
	if err := e.Parse(a, MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	if err := dst.Parse(b, MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	want := fields(&e)
	if got := e.CloneTo(&dst); got != &dst || fields(&dst) != want {
		t.Errorf("CloneTo = %s, want %s returned as dst", fields(&dst), want)
	}
	if string(a) != testEvent || string(b) != testHeaderOnly+"k=v" {
		t.Errorf("inputs after CloneTo = %q, %q, want %q, %q", a, b, testEvent, testHeaderOnly+"k=v")
	}
	other := []byte(testHeaderOnly + "a=1 b=2")
	if err := e.Parse(other, MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	if fields(&dst) != want {
		t.Errorf("copy after e parses again = %s, want %s", fields(&dst), want)
	}
}

func TestEventCloneToSelfDetaches(t *testing.T) {
	input := []byte(testEvent)
	var e Event
	if err := e.Parse(input, MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	want := fields(&e)
	e.CloneTo(&e)
	for i := range input {
		input[i] = 'X'
	}
	if got := fields(&e); got != want {
		t.Errorf("e.CloneTo(e) after the input changed = %s, want %s", got, want)
	}
	if got := fields(e.CloneTo(&e)); got != want {
		t.Errorf("a second e.CloneTo(e) = %s, want %s", got, want)
	}
}

func TestEventCloneToDropsLargeOwnedBytes(t *testing.T) {
	large := []byte(testHeaderOnly + "msg=" + strings.Repeat("x", 100<<10))
	var dst Event
	if err := dst.UnmarshalText(large); err != nil {
		t.Fatalf("UnmarshalText = %v, want nil", err)
	}
	if cap(dst.owned) < len(large) {
		t.Fatalf("owned bytes = %d, want room for %d", cap(dst.owned), len(large))
	}
	e := parsed(t, testEvent)
	e.CloneTo(&dst)
	if cap(dst.owned) > 64<<10 {
		t.Errorf("owned bytes after a small copy = %d, want at most 65536", cap(dst.owned))
	}
	var big Event
	if err := big.Parse(large, MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	var keep Event
	big.CloneTo(&keep)
	assertAllocs(t, 0, func() { big.CloneTo(&keep) })
	held := make([]byte, 100<<10)
	assertAllocs(t, 1, func() {
		dst.owned = held
		e.CloneTo(&dst)
	})
}

func TestEventCloneOfAPartialEvent(t *testing.T) {
	var e Event
	if err := e.Parse([]byte("CEF:3|Vendor|Prod"), MaxExtensions); !errors.Is(err, ErrIncompleteHeader) {
		t.Fatalf("Parse = %v, want ErrIncompleteHeader", err)
	}
	c := e.Clone()
	if got, want := fields(c), fields(&e); got != want {
		t.Errorf("Clone of a partial event = %s, want %s", got, want)
	}
	if c.DeviceEventClassID() != (Span{}) {
		t.Errorf("Clone: DeviceEventClassID() = %v, want the zero Span", c.DeviceEventClassID())
	}
}

func TestEventCloneAllocs(t *testing.T) {
	withPairs, header, pipes := parsed(t, testEvent), parsed(t, testHeaderOnly), parsed(t, "CEF:0|||||||")
	var zero, version Event
	if err := version.Parse([]byte("CEF:7|"), MaxExtensions); !errors.Is(err, ErrIncompleteHeader) {
		t.Fatalf("Parse(CEF:7|) = %v, want ErrIncompleteHeader", err)
	}
	var kept *Event
	assertAllocs(t, 3, func() { kept = withPairs.Clone() })
	assertAllocs(t, 2, func() { kept = header.Clone() })
	assertAllocs(t, 2, func() { kept = pipes.Clone() })
	assertAllocs(t, 1, func() { kept = version.Clone() })
	assertAllocs(t, 1, func() { kept = zero.Clone() })
	_ = kept
	var dst Event
	assertAllocs(t, 0, func() { withPairs.CloneTo(&dst) })
}

func TestEventCloneToSizesThePairsToTheCopy(t *testing.T) {
	var src, dst, fresh Event
	if err := src.Parse(pairsLine(17), 17); err != nil {
		t.Fatalf("Parse(pairsLine(17), 17) = %v, want nil", err)
	}
	if err := dst.Parse(pairsLine(16), 16); err != nil {
		t.Fatalf("Parse(pairsLine(16), 16) = %v, want nil", err)
	}
	if got := cap(src.Clone().pairs); got != 17 {
		t.Errorf("pair storage of a Clone of 17 pairs = %d pairs, want 17", got)
	}
	if got := cap(src.CloneTo(&fresh).pairs); got != 17 {
		t.Errorf("pair storage of a fresh Event after CloneTo of 17 pairs = %d pairs, want 17", got)
	}
	if got := cap(src.CloneTo(&dst).pairs); got != 17 {
		t.Errorf("pair storage of 16 pairs after CloneTo of 17 = %d pairs, want 17", got)
	}
	first := &dst.pairs[0]
	src.CloneTo(&dst)
	if cap(dst.pairs) != 17 || &dst.pairs[0] != first {
		t.Errorf("CloneTo into storage of 17 pairs = %d pairs, moved %t, want the 17 kept", cap(dst.pairs),
			&dst.pairs[0] != first)
	}
}

func TestEventAppendTextRoundTrips(t *testing.T) {
	var e, back Event
	for _, c := range corpusLines(t) {
		if err := e.Parse(c.line, MaxExtensions); err != nil && !e.HeaderComplete() {
			continue
		}
		text, err := e.AppendText(nil)
		if err != nil {
			t.Errorf("%s: AppendText = %v, want nil", c.name, err)
			continue
		}
		if err := back.UnmarshalText(text); err != nil || fields(&back) != fields(&e) {
			t.Errorf("%s: UnmarshalText(%q) = %v, %s, want %s", c.name, text, err, fields(&back), fields(&e))
		}
	}
}

func TestEventAppendTextIsCanonical(t *testing.T) {
	e := parsed(t, "CEF:   7|V|P|1|C|N|5|   a=1  b=2   \r\n")
	text, err := e.AppendText([]byte("> "))
	if want := "> CEF:7|V|P|1|C|N|5|a=1  b=2"; err != nil || string(text) != want {
		t.Errorf("AppendText = %q, %v, want %q", text, err, want)
	}
	marshaled, err := e.MarshalText()
	if want := "CEF:7|V|P|1|C|N|5|a=1  b=2"; err != nil || string(marshaled) != want {
		t.Errorf("MarshalText = %q, %v, want %q", marshaled, err, want)
	}
}

func TestEventAppendTextTakesMaxExtensionsPairs(t *testing.T) {
	line := pairsLine(256)
	e := parsed(t, string(line))
	if text, err := e.AppendText(nil); err != nil || !bytes.Equal(text, line) {
		t.Errorf("AppendText of 256 pairs = %q, %v, want the input", text, err)
	}
}

func TestEventAppendTextFails(t *testing.T) {
	partial := new(Event)
	if err := partial.Parse([]byte("CEF:0|V|P\xff"), MaxExtensions); !errors.Is(err, ErrIncompleteHeader) {
		t.Fatalf("Parse of a partial header = %v, want ErrIncompleteHeader", err)
	}
	overflow := new(Event)
	if err := overflow.Parse(pairsLine(257), 300); err != nil {
		t.Fatalf("Parse(pairsLine(257), 300) = %v, want nil", err)
	}
	badUTF8 := parsed(t, testHeaderOnly+"msg=\xff")
	cut := new(Event)
	if err := cut.Parse([]byte(testHeaderOnly+"a=1  b=2"), 1); !errors.Is(err, ErrExtOverflow) {
		t.Fatalf("Parse(a=1  b=2, 1) = %v, want ErrExtOverflow", err)
	}
	overflowUTF8 := new(Event)
	if err := overflowUTF8.Parse(append(pairsLine(257), " x=\xff"...), 300); err != nil {
		t.Fatalf("Parse(pairsLine(257) x=\\xff, 300) = %v, want nil", err)
	}
	reset := parsed(t, testEvent)
	reset.Reset()
	for _, tc := range []struct {
		name string
		e    *Event
		err  error
	}{
		{"zero", new(Event), ErrIncompleteHeader},
		{"reset", reset, ErrIncompleteHeader},
		{"partial header, not UTF-8", partial, ErrIncompleteHeader},
		{"257 pairs", overflow, ErrExtOverflow},
		{"a limit cut before two spaces", cut, ErrExtOverflow},
		{"258 pairs, not UTF-8", overflowUTF8, ErrExtOverflow},
		{"not UTF-8", badUTF8, ErrInvalidUTF8},
	} {
		dst := []byte("keep")
		got, err := tc.e.AppendText(dst)
		if !errors.Is(err, tc.err) || string(got) != "keep" {
			t.Errorf("%s: AppendText = %q, %v, want %q, %v", tc.name, got, err, "keep", tc.err)
		}
		if text, err := tc.e.MarshalText(); text != nil || !errors.Is(err, tc.err) {
			t.Errorf("%s: MarshalText = %q, %v, want nil, %v", tc.name, text, err, tc.err)
		}
	}
}

func TestEventAppendTextAllocs(t *testing.T) {
	e := parsed(t, testEvent)
	dst := make([]byte, 0, 256)
	var text []byte
	var err error
	assertAllocs(t, 0, func() { text, err = e.AppendText(dst) })
	assertAllocs(t, 1, func() { text, err = e.MarshalText() })
	if err != nil || string(text) != testEvent {
		t.Errorf("MarshalText = %q, %v, want the input", text, err)
	}
	var zero Event
	assertAllocs(t, 0, func() { text, err = zero.MarshalText() })
	if text != nil || !errors.Is(err, ErrIncompleteHeader) {
		t.Errorf("MarshalText of the zero Event = %q, %v, want nil, ErrIncompleteHeader", text, err)
	}
	// 81 bytes is one past an allocation size class.
	sized := "CEF:0|V|P|1|C|N|5|msg=" + strings.Repeat("x", 59)
	e = parsed(t, sized)
	assertAllocs(t, 1, func() { text, err = e.MarshalText() })
	if err != nil || string(text) != sized {
		t.Errorf("MarshalText = %q, %v, want the %d-byte input", text, err, len(sized))
	}
}

func TestEventAppendTextAllocsAtEachVersionLength(t *testing.T) {
	for _, v := range []int{0, 9, 10, 99, 100, 999, 1000, 9999} {
		// 81 bytes is one past an allocation size class.
		head := "CEF:" + strconv.Itoa(v) + "|V|P|1|C|N|5|msg="
		line := head + strings.Repeat("x", 81-len(head))
		e := parsed(t, line)
		dst := make([]byte, 0, len(line))
		var text []byte
		var err error
		assertAllocs(t, 0, func() { text, err = e.AppendText(dst) })
		if err != nil || string(text) != line {
			t.Errorf("AppendText into %d bytes = %q, %v, want the input", cap(dst), text, err)
		}
		assertAllocs(t, 1, func() { text, err = e.MarshalText() })
		if err != nil || string(text) != line {
			t.Errorf("MarshalText = %q, %v, want the %d-byte input", text, err, len(line))
		}
	}
}

func TestEventUnmarshalTextCopiesTheText(t *testing.T) {
	text := []byte(testEvent)
	var e Event
	if err := e.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText = %v, want nil", err)
	}
	want := fields(&e)
	for i := range text {
		text[i] = 'X'
	}
	if got := fields(&e); got != want {
		t.Errorf("after the text changed = %s, want %s", got, want)
	}
}

func TestEventUnmarshalTextKeepsThePartialEvent(t *testing.T) {
	var e Event
	err := e.UnmarshalText([]byte("CEF:0|Vendor|Pro"))
	if pe := asParseError(err); pe == nil || !errors.Is(err, ErrIncompleteHeader) || pe.Position != 16 {
		t.Fatalf("UnmarshalText of a partial header = %v, want ErrIncompleteHeader at byte 16", err)
	}
	if e.Text(e.DeviceVendor()) != "Vendor" || e.Text(e.DeviceProduct()) != "Pro" || e.HeaderComplete() {
		t.Errorf("partial event = %s, want Vendor and Pro kept", fields(&e))
	}
	if err := e.UnmarshalText(nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("UnmarshalText(nil) = %v, want ErrEmpty", err)
	}
}

func TestEventUnmarshalTextTakesMaxExtensionsPairs(t *testing.T) {
	for _, tc := range []struct {
		pairs int
		err   error
	}{{256, nil}, {257, ErrExtOverflow}} {
		line := pairsLine(tc.pairs)
		var e Event
		err := e.UnmarshalText(line)
		diff := eventDiff(&e, err, refParse(line, 256))
		if diff != "" || !errors.Is(err, tc.err) || e.ExtCount() != 256 {
			t.Errorf("UnmarshalText(pairsLine(%d)) = %v, %s, %d pairs, want %v and 256 pairs",
				tc.pairs, err, diff, e.ExtCount(), tc.err)
		}
	}
}

func TestEventUnmarshalTextAllocs(t *testing.T) {
	text := []byte(testEvent)
	var e Event
	var err error
	assertAllocs(t, 0, func() { err = e.UnmarshalText(text) })
	if err != nil {
		t.Errorf("UnmarshalText = %v, want nil", err)
	}
	bad := []byte("CEF:x")
	assertAllocs(t, 1, func() { err = e.UnmarshalText(bad) })
	if !errors.Is(err, ErrVersion) {
		t.Errorf("UnmarshalText(%q) = %v, want ErrVersion", bad, err)
	}
	held := make([]byte, 100<<10)
	assertAllocs(t, 1, func() {
		e.owned = held
		err = e.UnmarshalText(text)
	})
	if err != nil || cap(e.owned) != len(text) {
		t.Errorf("UnmarshalText after 100 KiB = %v with %d owned bytes, want nil with %d", err, cap(e.owned), len(text))
	}
}

// textOf returns a valid text of n bytes, n at least 40: testHeaderOnly and one pair.
func textOf(n int) []byte {
	return []byte(testHeaderOnly + "msg=" + strings.Repeat("x", n-len(testHeaderOnly)-len("msg=")))
}

func TestEventUnmarshalTextReusesOwnedBytes(t *testing.T) {
	for _, tc := range []struct {
		held, next, want int
	}{
		{64, 64, 64},
		{65536, 64, 65536},
		{65537, 64, 64},
		{65537, 65536, 65536},
		{100 << 10, 65537, 100 << 10},
	} {
		var e Event
		if err := e.UnmarshalText(textOf(tc.held)); err != nil {
			t.Fatalf("UnmarshalText of %d bytes = %v, want nil", tc.held, err)
		}
		if err := e.UnmarshalText(textOf(tc.next)); err != nil {
			t.Fatalf("UnmarshalText of %d bytes = %v, want nil", tc.next, err)
		}
		if got := cap(e.owned); got != tc.want {
			t.Errorf("owned bytes after texts of %d and %d bytes = %d, want %d", tc.held, tc.next, got, tc.want)
		}
	}
}

func TestEventResetAnswersAsTheZeroEvent(t *testing.T) {
	e := parsed(t, string(pairsLine(40)))
	storage := cap(e.pairs)
	e.Reset()
	var zero Event
	if got, want := fields(e), fields(&zero); got != want {
		t.Errorf("after Reset = %s, want %s", got, want)
	}
	if b := e.Bytes(Span{Start: 0, End: 1}); b == nil || len(b) != 0 || cap(b) != 0 {
		t.Errorf("Bytes([0:1]) after Reset = %q cap %d (nil %t), want an empty view", b, cap(b), b == nil)
	}
	if got := cap(e.pairs); got != storage {
		t.Errorf("pair storage after Reset = %d, want %d", got, storage)
	}
	assertAllocs(t, 0, e.Reset)
}

func TestEventStringSummarizes(t *testing.T) {
	long := strings.Repeat("v", 31)
	for _, tc := range []struct {
		line string
		want string
	}{
		{testHeaderOnly, "Event{ver=0 vendor=Vendor product=Product devver=1.0 classid=100 name=Name sev=5 exts=0}"},
		{"CEF:1|V|P|1|C|N|5|a=1 b=" + long + " c=3 d=4",
			"Event{ver=1 vendor=V product=P devver=1 classid=C name=N sev=5 exts=4[a=1 b=" + long[:30] +
				"... c=3 ...]}"},
		{"CEF:1|V|P|1|C|N|5|a=1 b=" + long[:30] + " c=3",
			"Event{ver=1 vendor=V product=P devver=1 classid=C name=N sev=5 exts=3[a=1 b=" + long[:30] +
				" c=3]}"},
		{"CEF:1|V\rX|P\nY|1|C|N\r\n|5|a=x\r\ny b=\n",
			"Event{ver=1 vendor=V X product=P Y devver=1 classid=C name=N   sev=5 exts=2[a=x  y b=]}"},
		{"CEF:1|V|P|1|C|N|5|a=\rb",
			"Event{ver=1 vendor=V product=P devver=1 classid=C name=N sev=5 exts=1[a= b]}"},
		{"CEF:1|V|P|1|C|N|5|a=\x0cb",
			"Event{ver=1 vendor=V product=P devver=1 classid=C name=N sev=5 exts=1[a=\x0cb]}"},
	} {
		if got := parsed(t, tc.line).String(); got != tc.want {
			t.Errorf("String() of %q = %q, want %q", tc.line, got, tc.want)
		}
	}
	var zero Event
	if got, want := zero.String(), "Event{ver=0 vendor= product= devver= classid= name= sev= exts=0}"; got != want {
		t.Errorf("String() of the zero Event = %q, want %q", got, want)
	}
	e := parsed(t, string(pairsLine(10)))
	assertAllocs(t, 1, func() { _ = e.String() })
	lines := parsed(t, "CEF:1|V\rX|P\nY|1|C|N|5|a=x\r\ny b=2")
	assertAllocs(t, 1, func() { _ = lines.String() })
}

// TestEventStringWritesEachLineBreakAsASpace puts one CR or LF at every position of a
// header field, the last header field and a value of 1 to 20 bytes.
func TestEventStringWritesEachLineBreakAsASpace(t *testing.T) {
	for n := 1; n <= 20; n++ {
		for i := range n {
			field := []byte(strings.Repeat("1", n))
			field[i] = "\r\n"[i%2]
			for _, line := range []string{
				"CEF:0|" + string(field), "CEF:0|" + string(field) + "|P|1|C|N|5|",
				"CEF:0|V|P|1|C|N|" + string(field) + "|", testHeaderOnly + "a=" + string(field) + " b=2",
			} {
				var e Event
				want := refParse([]byte(line), MaxExtensions)
				if diff := eventDiff(&e, e.Parse([]byte(line), MaxExtensions), want); diff != "" {
					t.Fatalf("Parse(%q): %s", line, diff)
				}
				if got, summary := e.String(), refSummary([]byte(line), want); got != summary {
					t.Errorf("String() of %q = %q, want %q", line, got, summary)
				}
			}
		}
	}
}

// TestEventStringAllocsOnceAcrossLengths reads summaries of 64 consecutive lengths, so
// that some of them end just past an allocation size class.
func TestEventStringAllocsOnceAcrossLengths(t *testing.T) {
	key, value := strings.Repeat("k", 30), strings.Repeat("v", 40)
	pairs := strings.Repeat(" "+key+"="+value, 3) + strings.Repeat(" a=1", 97)
	for n := range 64 {
		e := parsed(t, "CEF:9999|"+strings.Repeat("x", n)+"|P|1|C|N|5|"+pairs[1:])
		var summary string
		assertAllocs(t, 1, func() { summary = e.String() })
		if !strings.Contains(summary, " exts=100[") {
			t.Fatalf("String() = %q, want 100 pairs", summary)
		}
	}
}

func FuzzEventAppendText(f *testing.F) {
	f.Add([]byte(testEvent), 3)
	f.Add([]byte(testHeaderOnly+"a=\xff"), 256)
	f.Add(pairsLine(257), 300)
	f.Add([]byte("CEF:0|||||||0=  0="), 1)
	f.Fuzz(func(t *testing.T, input []byte, limit int) {
		limit %= 300
		var e Event
		want := refParse(input, limit)
		if diff := eventDiff(&e, e.Parse(input, limit), want); diff != "" {
			t.Fatalf("Parse(%q, %d): %s", input, limit, diff)
		}
		checkUnmarshalInput(t, input)
		text, err := e.AppendText(nil)
		if class := refTextFault(input, want); class != nil {
			marshaled, marshalErr := e.MarshalText()
			if !errors.Is(err, class) || text != nil || !errors.Is(marshalErr, class) || marshaled != nil {
				t.Fatalf("AppendText, MarshalText of %q = %q, %v and %q, %v, want nil, %v from both",
					input, text, err, marshaled, marshalErr, class)
			}
			return
		}
		if wantText := refText(input, want); err != nil || string(text) != wantText {
			t.Fatalf("AppendText of %q = %q, %v, want %q", input, text, err, wantText)
		}
		checkReadBack(t, &e, text)
	})
}

// checkUnmarshalInput fails t unless UnmarshalText of input gives the reference parse
// of input under MaxExtensions, over bytes equal to input.
func checkUnmarshalInput(t *testing.T, input []byte) {
	t.Helper()
	var u Event
	diff := eventDiff(&u, u.UnmarshalText(input), refParse(input, MaxExtensions))
	if diff != "" || !bytes.Equal(u.raw, input) {
		t.Fatalf("UnmarshalText(%q) = %s, bytes %q, want the reference parse of a copy", input, diff, u.raw)
	}
}

// checkReadBack fails t unless MarshalText gives text, the AppendText of e, and
// UnmarshalText reads text back to an Event equal to e that the reference agrees with.
func checkReadBack(t *testing.T, e *Event, text []byte) {
	t.Helper()
	if marshaled, err := e.MarshalText(); err != nil || !bytes.Equal(text, marshaled) {
		t.Fatalf("MarshalText = %q, %v, want AppendText's %q", marshaled, err, text)
	}
	var back Event
	err := back.UnmarshalText(text)
	if diff := eventDiff(&back, err, refParse(text, 256)); diff != "" || fields(&back) != fields(e) {
		t.Fatalf("UnmarshalText(%q) = %s, %s, want %s", text, diff, fields(&back), fields(e))
	}
}

// refText returns the text of the header-complete reference event want of input: the
// version in decimal, the six header fields and the bytes from the first key to the
// last value.
func refText(input []byte, want *refEvent) string {
	text := "CEF:" + strconv.Itoa(want.version) + "|" + string(input[want.header[0].start:want.header[5].end]) + "|"
	if n := len(want.pairs); n > 0 {
		text += string(input[want.pairs[0].key.start:want.pairs[n-1].value.end])
	}
	return text
}

// refTextFault returns what the text methods give for the reference event want of
// input: ErrIncompleteHeader unless headerComplete, then ErrExtOverflow above 256 pairs
// or for a last value ending in a space, CR or LF, then ErrInvalidUTF8; nil otherwise.
func refTextFault(input []byte, want *refEvent) error {
	switch {
	case !want.headerComplete:
		return ErrIncompleteHeader
	case len(want.pairs) > 256 || refTrailing(input, want):
		return ErrExtOverflow
	case !utf8.Valid(input[want.header[0].start:refEnd(want)]):
		return ErrInvalidUTF8
	}
	return nil
}

// refTrailing reports whether the last reference value of input ends in a space, a CR
// or an LF.
func refTrailing(input []byte, want *refEvent) bool {
	if len(want.pairs) == 0 {
		return false
	}
	last := want.pairs[len(want.pairs)-1].value
	return last.end > last.start && strings.IndexByte(" \r\n", input[last.end-1]) >= 0
}

// refEnd returns the end of the bytes a header-complete reference event's spans cover.
func refEnd(want *refEvent) int {
	if n := len(want.pairs); n > 0 {
		return want.pairs[n-1].value.end
	}
	return want.header[5].end
}

func FuzzEventClone(f *testing.F) {
	f.Add([]byte(testEvent), []byte(testHeaderOnly+"k=v"))
	f.Add([]byte("CEF:0|V|P"), []byte(""))
	f.Fuzz(func(t *testing.T, input, other []byte) {
		input = bytes.Clone(input)
		var e, dst Event
		if diff := eventDiff(&e, e.Parse(input, MaxExtensions), refParse(input, MaxExtensions)); diff != "" {
			t.Fatalf("Parse(%q): %s", input, diff)
		}
		want := fields(&e)
		c := e.Clone()
		if diff := eventDiff(&dst, dst.Parse(other, MaxExtensions), refParse(other, MaxExtensions)); diff != "" {
			t.Fatalf("Parse(%q): %s", other, diff)
		}
		kept := bytes.Clone(other)
		e.CloneTo(&dst)
		e.CloneTo(&e)
		for i := range input {
			input[i] = 'X'
		}
		for name, got := range map[string]*Event{"Clone": c, "CloneTo": &dst, "CloneTo(e)": &e} {
			if fields(got) != want {
				t.Fatalf("%s of %q = %s, want %s", name, input, fields(got), want)
			}
		}
		e.CloneTo(c)
		clear(e.owned)
		if got := fields(c); got != want || !bytes.Equal(other, kept) {
			t.Fatalf("CloneTo(clone) = %s, dst's input %q, want %s and %q unchanged", got, other, want, kept)
		}
		e.Reset()
		var zero Event
		if fields(&e) != fields(&zero) {
			t.Fatalf("after Reset = %s, want the zero event", fields(&e))
		}
	})
}

func FuzzEventExt(f *testing.F) {
	f.Add([]byte(testEvent), []byte("src"), -1)
	f.Add([]byte(testHeaderOnly+"abcd=1 abcde=2 abcd=3"), []byte("abcd"), 3)
	f.Add([]byte(testHeaderOnly+"k=v"), []byte("k"), math.MinInt)
	f.Fuzz(func(t *testing.T, input, key []byte, at int) {
		var e Event
		want := refParse(input, MaxExtensions)
		if diff := eventDiff(&e, e.Parse(input, MaxExtensions), want); diff != "" {
			t.Fatalf("Parse(%q): %s", input, diff)
		}
		if diff := pairsDiff(&e, want, at); diff != "" {
			t.Fatalf("on %q: %s", input, diff)
		}
		value, found := refLookup(input, want, key)
		if got, ok := e.Ext(key); ok != found || (found && !spanIs(got, value)) || (!found && got != Span{}) {
			t.Fatalf("Ext(%q) on %q = %v, %t, want %v, %t", key, input, got, ok, value, found)
		}
		bytesSpan, bytesOK := e.Ext(key)
		if got, ok := e.ExtString(string(key)); got != bytesSpan || ok != bytesOK {
			t.Fatalf("ExtString(%q) on %q = %v, %t, want Ext's %v, %t", key, input, got, ok, bytesSpan, bytesOK)
		}
	})
}

// pairsDiff compares the pairs All yields, in input order, and the answer of ExtAt(at)
// with the reference pairs of want, and returns the first difference, or "" for none.
func pairsDiff(e *Event, want *refEvent, at int) string {
	if p, ok := e.ExtAt(at); ok != (at >= 0 && at < len(want.pairs)) || (!ok && p != ExtPair{}) {
		return fmt.Sprintf("ExtAt(%d) of %d pairs = %v, %t, want true inside the pairs only",
			at, len(want.pairs), p, ok)
	}
	i := 0
	for k, v := range e.All() {
		if i == len(want.pairs) || !spanIs(k, want.pairs[i].key) || !spanIs(v, want.pairs[i].value) {
			return fmt.Sprintf("All() pair %d = %v=%v, want the reference pair %d of %d", i, k, v, i, len(want.pairs))
		}
		i++
	}
	if i != len(want.pairs) {
		return fmt.Sprintf("All() = %d pairs, want %d", i, len(want.pairs))
	}
	return ""
}

// refLookup returns the value of the last reference pair of input whose key is key.
func refLookup(input []byte, want *refEvent, key []byte) (value refSpan, found bool) {
	for _, p := range want.pairs {
		if bytes.Equal(input[p.key.start:p.key.end], key) {
			value, found = p.value, true
		}
	}
	return value, found
}

func FuzzEventBytes(f *testing.F) {
	f.Add([]byte(testEvent), uint32(0), uint32(4))
	f.Add([]byte(testHeaderOnly), uint32(1<<31), uint32(1<<31+1))
	f.Fuzz(func(t *testing.T, input []byte, start, end uint32) {
		var e Event
		if diff := eventDiff(&e, e.Parse(input, MaxExtensions), refParse(input, MaxExtensions)); diff != "" {
			t.Fatalf("Parse(%q): %s", input, diff)
		}
		s := Span{Start: start, End: end}
		got := e.Bytes(s)
		want, inRange := refBytes(input, uint64(start), uint64(end))
		if (!inRange && got == nil) || !bytes.Equal(got, want) || cap(got) != len(want) {
			t.Fatalf("Bytes(%v) on %d bytes = %q cap %d, want %q capped", s, len(input), got, cap(got), want)
		}
		if text := e.Text(s); text != string(want) {
			t.Fatalf("Text(%v) = %q, want %q", s, text, want)
		}
		if got, wantApp := e.AppendBytes([]byte("x"), s), append([]byte("x"), want...); !bytes.Equal(got, wantApp) {
			t.Fatalf("AppendBytes(x, %v) = %q, want %q", s, got, wantApp)
		}
	})
}

// refBytes returns input[start:end], computed in uint64, and whether the range lies in
// input.
func refBytes(input []byte, start, end uint64) ([]byte, bool) {
	if start > end || end > uint64(len(input)) {
		return nil, false
	}
	return input[start:end], true
}

func FuzzEventString(f *testing.F) {
	f.Add([]byte(testEvent))
	f.Fuzz(func(t *testing.T, input []byte) {
		var e Event
		want := refParse(input, MaxExtensions)
		if diff := eventDiff(&e, e.Parse(input, MaxExtensions), want); diff != "" {
			t.Fatalf("Parse(%q): %s", input, diff)
		}
		got := e.String()
		if strings.IndexByte(got, '\r') >= 0 || strings.IndexByte(got, '\n') >= 0 {
			t.Fatalf("String() of %q = %q, want no CR or LF", input, got)
		}
		if summary := refSummary(input, want); got != summary {
			t.Fatalf("String() of %q = %q, want %q", input, got, summary)
		}
	})
}

// refSummary returns the summary of the reference event want of input, built with
// strconv: the version, the header fields, the pair count and the first three pairs,
// each value cut at 30 bytes, CR and LF replaced by spaces.
func refSummary(input []byte, want *refEvent) string {
	text := func(s refSpan) string {
		return strings.ReplaceAll(strings.ReplaceAll(string(input[s.start:s.end]), "\r", " "), "\n", " ")
	}
	var b strings.Builder
	b.WriteString("Event{ver=" + strconv.Itoa(want.version))
	for i, label := range []string{"vendor", "product", "devver", "classid", "name", "sev"} {
		b.WriteString(" " + label + "=" + text(want.header[i]))
	}
	b.WriteString(" exts=" + strconv.Itoa(len(want.pairs)))
	if len(want.pairs) == 0 {
		return b.String() + "}"
	}
	shown := make([]string, 0, 3)
	for _, p := range want.pairs[:min(3, len(want.pairs))] {
		v := text(p.value)
		if len(v) > 30 {
			v = v[:30] + "..."
		}
		shown = append(shown, text(p.key)+"="+v)
	}
	if len(want.pairs) > 3 {
		shown = append(shown, "...")
	}
	return b.String() + "[" + strings.Join(shown, " ") + "]}"
}

// refFields returns fields of the Event the reference event want of input describes.
func refFields(input []byte, want *refEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "v%d headerComplete=%t n=%d", want.version, want.headerComplete, len(want.pairs))
	for _, s := range want.header {
		fmt.Fprintf(&b, "|%q", input[s.start:s.end])
	}
	for _, p := range want.pairs {
		fmt.Fprintf(&b, " %q=%q", input[p.key.start:p.key.end], input[p.value.start:p.value.end])
	}
	return b.String()
}

func FuzzSpan(f *testing.F) {
	f.Add(uint32(0), uint32(4294967295))
	f.Fuzz(func(t *testing.T, start, end uint32) {
		s := Span{Start: start, End: end}
		wantLen := uint32(0)
		if end > start {
			wantLen = end - start
		}
		if s.Len() != wantLen || s.IsEmpty() != (wantLen == 0) {
			t.Fatalf("%v.Len(), IsEmpty() = %d, %t, want %d, %t", s, s.Len(), s.IsEmpty(), wantLen, wantLen == 0)
		}
		want := "[" + strconv.FormatUint(uint64(start), 10) + ":" + strconv.FormatUint(uint64(end), 10) + "]"
		if got := s.String(); got != want {
			t.Fatalf("String() = %q, want %q", got, want)
		}
		p := ExtPair{Key: s, Value: Span{Start: end, End: start}}
		wantPair := want + "=[" + strconv.FormatUint(uint64(end), 10) + ":" +
			strconv.FormatUint(uint64(start), 10) + "]"
		if got := p.String(); got != wantPair {
			t.Fatalf("ExtPair.String() = %q, want %q", got, wantPair)
		}
	})
}

func FuzzVersionString(f *testing.F) {
	f.Add(9999)
	f.Fuzz(func(t *testing.T, v int) {
		if got, want := Version(v).String(), strconv.Itoa(v); got != want {
			t.Fatalf("Version(%d).String() = %q, want %q", v, got, want)
		}
	})
}

func BenchmarkEventAccessors(b *testing.B) {
	e := parsed(b, testEvent)
	header := [...]string{e.Text(e.DeviceVendor()), e.Text(e.DeviceProduct()), e.Text(e.DeviceVersion()),
		e.Text(e.DeviceEventClassID()), e.Text(e.Name()), e.Text(e.Severity())}
	want := [...]string{"Security", "threatmanager", "1.0", "100", "worm successfully stopped", "10"}
	if header != want {
		b.Fatalf("header fields = %q, want %q", header, want)
	}
	if e.Version() != 0 || !e.HeaderComplete() || e.ExtCount() != 4 {
		b.Fatalf("Version(), HeaderComplete(), ExtCount() = %d, %t, %d, want 0, true, 4", e.Version(),
			e.HeaderComplete(), e.ExtCount())
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _, _, _, _ = e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(), e.Name()
		_, _, _, _ = e.Severity(), e.Version(), e.HeaderComplete(), e.ExtCount()
	}
}

func BenchmarkEventExtAt(b *testing.B) {
	line := pairsLine(58)
	e, want := parsed(b, string(line)), refParse(line, MaxExtensions)
	for i, w := range want.pairs {
		if p, ok := e.ExtAt(i); !ok || !spanIs(p.Key, w.key) || !spanIs(p.Value, w.value) {
			b.Fatalf("ExtAt(%d) = %v, %t, want [%d:%d]=[%d:%d]", i, p, ok,
				w.key.start, w.key.end, w.value.start, w.value.end)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		for i := range e.ExtCount() {
			_, _ = e.ExtAt(i)
		}
	}
}

func BenchmarkEventAll(b *testing.B) {
	line := pairsLine(58)
	e, want := parsed(b, string(line)), refParse(line, MaxExtensions)
	var got []string
	for k, v := range e.All() {
		got = append(got, fmt.Sprint(k, v))
	}
	wantPairs := make([]string, 0, len(want.pairs))
	for _, w := range want.pairs {
		wantPairs = append(wantPairs, fmt.Sprintf("[%d:%d] [%d:%d]", w.key.start, w.key.end,
			w.value.start, w.value.end))
	}
	if strings.Join(got, " ") != strings.Join(wantPairs, " ") {
		b.Fatalf("All() = %q, want %q", got, wantPairs)
	}
	b.ReportAllocs()
	for b.Loop() {
		for k := range e.All() {
			_ = k
		}
	}
}

func BenchmarkEventExtString(b *testing.B) {
	line := pairsLine(17)
	e, ref := parsed(b, string(line)), refParse(line, MaxExtensions)
	for _, key := range []string{"key0", "key8", "key16", "missing"} {
		b.Run(key, func(b *testing.B) {
			value, found := refLookup(line, ref, []byte(key))
			s, ok := e.ExtString(key)
			want := string(line[value.start:value.end])
			if ok != found || found == (key == "missing") || e.Text(s) != want {
				b.Fatalf("ExtString(%q) = %q, %t, want %q, %t", key, e.Bytes(s), ok, want, key != "missing")
			}
			b.ReportAllocs()
			for b.Loop() {
				_, _ = e.ExtString(key)
			}
		})
	}
}

func BenchmarkEventExt(b *testing.B) {
	e := parsed(b, string(pairsLine(17)))
	key := []byte("key8")
	if s, ok := e.Ext(key); !ok || e.Text(s) != "10.1.2.3" {
		b.Fatalf("Ext(key8) = %q, %t, want %q, true", e.Bytes(s), ok, "10.1.2.3")
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = e.Ext(key)
	}
}

func BenchmarkEventBytes(b *testing.B) {
	e := parsed(b, testEvent)
	if got := e.Bytes(e.DeviceVendor()); string(got) != "Security" {
		b.Fatalf("Bytes(DeviceVendor()) = %q, want %q", got, "Security")
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = e.Bytes(e.DeviceVendor())
	}
}

func BenchmarkEventText(b *testing.B) {
	e := parsed(b, testEvent)
	if got := e.Text(e.DeviceVendor()); got != "Security" {
		b.Fatalf("Text(DeviceVendor()) = %q, want %q", got, "Security")
	}
	out := heapCell[string](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = e.Text(e.DeviceVendor())
	}
}

func BenchmarkEventAppendBytes(b *testing.B) {
	e := parsed(b, testEvent)
	dst := make([]byte, 0, 64)
	if got := e.AppendBytes(dst, e.DeviceVendor()); string(got) != "Security" {
		b.Fatalf("AppendBytes(dst, DeviceVendor()) = %q, want %q", got, "Security")
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = e.AppendBytes(dst, e.DeviceVendor())
	}
}

func BenchmarkEventClone(b *testing.B) {
	for _, n := range []int{10, 58} {
		e := parsed(b, string(pairsLine(n)))
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			if got, want := fields(e.Clone()), fields(e); got != want {
				b.Fatalf("fields of the Clone = %s, want %s", got, want)
			}
			out := heapCell[*Event](b)
			b.ReportAllocs()
			for b.Loop() {
				*out = e.Clone()
			}
		})
	}
}

func BenchmarkEventCloneTo(b *testing.B) {
	for _, n := range []int{10, 58} {
		e := parsed(b, string(pairsLine(n)))
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			var dst Event
			if got, want := fields(e.CloneTo(&dst)), fields(e); got != want {
				b.Fatalf("fields of the CloneTo copy = %s, want %s", got, want)
			}
			b.ReportAllocs()
			for b.Loop() {
				e.CloneTo(&dst)
			}
		})
	}
}

func BenchmarkEventAppendText(b *testing.B) {
	e := parsed(b, testEvent)
	dst := make([]byte, 0, 256)
	if text, err := e.AppendText(dst); err != nil || string(text) != testEvent {
		b.Fatalf("AppendText = %q, %v, want the input", text, err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := e.AppendText(dst); err != nil {
			b.Fatalf("AppendText = %v, want nil", err)
		}
	}
}

func BenchmarkEventMarshalText(b *testing.B) {
	e := parsed(b, testEvent)
	if text, err := e.MarshalText(); err != nil || string(text) != testEvent {
		b.Fatalf("MarshalText = %q, %v, want the input", text, err)
	}
	out := heapCell[[]byte](b)
	b.ReportAllocs()
	for b.Loop() {
		var err error
		if *out, err = e.MarshalText(); err != nil {
			b.Fatalf("MarshalText = %v, want nil", err)
		}
	}
}

func BenchmarkEventUnmarshalText(b *testing.B) {
	text := []byte(testEvent)
	var e Event
	err := e.UnmarshalText(text)
	if diff := eventDiff(&e, err, refParse(text, MaxExtensions)); diff != "" {
		b.Fatalf("UnmarshalText(%q): %s", text, diff)
	}
	if got, want := fields(&e), refFields(text, refParse(text, MaxExtensions)); got != want {
		b.Fatalf("fields after UnmarshalText = %s, want %s", got, want)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := e.UnmarshalText(text); err != nil {
			b.Fatalf("UnmarshalText = %v, want nil", err)
		}
	}
}

func BenchmarkEventReset(b *testing.B) {
	e := parsed(b, testEvent)
	e.Reset()
	var zero Event
	if got, want := fields(e), fields(&zero); got != want {
		b.Fatalf("fields after Reset = %s, want %s", got, want)
	}
	if got := e.Bytes(Span{Start: 0, End: 1}); got == nil || len(got) != 0 || cap(got) != 0 {
		b.Fatalf("Bytes([0:1]) after Reset = %q cap %d (nil %t), want an empty view", got, cap(got), got == nil)
	}
	b.ReportAllocs()
	for b.Loop() {
		e.Reset()
	}
}

func BenchmarkEventString(b *testing.B) {
	e := parsed(b, testEvent)
	if got, want := e.String(), refSummary([]byte(testEvent), refParse([]byte(testEvent), MaxExtensions)); got != want {
		b.Fatalf("String() = %q, want %q", got, want)
	}
	out := heapCell[string](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = e.String()
	}
}

func BenchmarkExtPairString(b *testing.B) {
	p := ExtPair{Key: Span{Start: 100, End: 103}, Value: Span{Start: 104, End: 112}}
	if got := p.String(); got != "[100:103]=[104:112]" {
		b.Fatalf("String() = %q, want %q", got, "[100:103]=[104:112]")
	}
	out := heapCell[string](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = p.String()
	}
}

func BenchmarkSpanString(b *testing.B) {
	s := Span{Start: 100, End: 4000}
	if got := s.String(); got != "[100:4000]" {
		b.Fatalf("String() = %q, want %q", got, "[100:4000]")
	}
	out := heapCell[string](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = s.String()
	}
}

func BenchmarkSpanLen(b *testing.B) {
	s := Span{Start: 100, End: 4000}
	if s.Len() != 3900 || s.IsEmpty() {
		b.Fatalf("Len(), IsEmpty() = %d, %t, want 3900, false", s.Len(), s.IsEmpty())
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = s.Len(), s.IsEmpty()
	}
}

func BenchmarkVersionString(b *testing.B) {
	for _, v := range []Version{1, 9999} {
		b.Run(strconv.Itoa(int(v)), func(b *testing.B) {
			if got, want := v.String(), strconv.Itoa(int(v)); got != want {
				b.Fatalf("Version(%d).String() = %q, want %q", int(v), got, want)
			}
			out := heapCell[string](b)
			b.ReportAllocs()
			for b.Loop() {
				*out = v.String()
			}
		})
	}
}

func ExampleEvent_ExtString() {
	var e Event
	if err := e.Parse([]byte(testHeaderOnly+"dvchost=first src=10.0.0.1 dvchost=last"), MaxExtensions); err != nil {
		fmt.Println(err)
		return
	}
	host, ok := e.ExtString("dvchost")
	fmt.Println(e.Text(host), ok)
	// Output: last true
}

func ExampleEvent_All() {
	var e Event
	if err := e.Parse([]byte(testHeaderOnly+`src=10.0.0.1 msg=a\=b`), MaxExtensions); err != nil {
		fmt.Println(err)
		return
	}
	for key, value := range e.All() {
		fmt.Printf("%s=%s\n", e.Bytes(key), UnescapeExtValue(e.Bytes(value), nil))
	}
	// Output:
	// src=10.0.0.1
	// msg=a=b
}

func ExampleEvent_CloneTo() {
	packet := []byte(testHeaderOnly + "act=allow")
	var e, kept Event
	if err := e.Parse(packet, MaxExtensions); err != nil {
		fmt.Println(err)
		return
	}
	e.CloneTo(&kept)
	copy(packet, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	act, _ := kept.ExtString("act")
	fmt.Println(kept.Text(kept.DeviceVendor()), kept.Text(act))
	// Output: Vendor allow
}

func ExampleEvent_AppendText() {
	line := []byte("CEF:  0|Vendor|Product|1.0|100|Name|5|  src=10.0.0.1   \r\n")
	var e Event
	if err := e.Parse(line, MaxExtensions); err != nil {
		fmt.Println(err)
		return
	}
	text, err := e.AppendText(nil)
	fmt.Printf("%s %v\n", text, err)
	// Output: CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1 <nil>
}
