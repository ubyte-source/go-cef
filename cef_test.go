package cef

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers (shared across all internal _test.go files in package cef)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Span & ExtPair
// ---------------------------------------------------------------------------

func TestSpanMethods(t *testing.T) {
	s := Span{Start: 5, End: 10}
	if s.Len() != 5 {
		t.Errorf("Len: got %d, want 5", s.Len())
	}
	if s.IsEmpty() {
		t.Error("expected not empty")
	}
	empty := Span{Start: 3, End: 3}
	if !empty.IsEmpty() {
		t.Error("expected empty")
	}
	if empty.Len() != 0 {
		t.Errorf("Len: got %d, want 0", empty.Len())
	}
}

func TestSpanLenInverted(t *testing.T) {
	s := Span{Start: 10, End: 5}
	if s.Len() != 0 {
		t.Errorf("inverted span Len: got %d, want 0", s.Len())
	}
	if !s.IsEmpty() {
		t.Error("inverted span should be empty")
	}
}

func TestSpanString(t *testing.T) {
	s := Span{Start: 5, End: 10}
	got := s.String()
	want := "[5:10]"
	if got != want {
		t.Errorf("Span.String() = %q, want %q", got, want)
	}
}

func TestExtPairString(t *testing.T) {
	p := ExtPair{Key: Span{5, 10}, Value: Span{11, 20}}
	got := p.String()
	want := "[5:10]=[11:20]"
	if got != want {
		t.Errorf("ExtPair.String() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Event accessors (Bytes, Text, Ext, ExtString, ExtAt, Extensions, All)
// ---------------------------------------------------------------------------

func TestGetOutOfRange(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4`))
	if err != nil {
		t.Fatal(err)
	}
	bad := Span{Start: 0, End: 999999}
	if got := e.Bytes(bad); got != nil {
		t.Errorf("expected nil for out-of-range Span, got %v", got)
	}
	if got := e.Text(bad); got != "" {
		t.Errorf("expected empty string for out-of-range Span, got %q", got)
	}
}

func TestGetNilEvent(t *testing.T) {
	e := &Event{}
	if got := e.Bytes(Span{0, 5}); got != nil {
		t.Errorf("expected nil for nil-raw Event, got %v", got)
	}
}

func TestGetInvertedSpan(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|`))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Bytes(Span{Start: 10, End: 5}); got != nil {
		t.Errorf("expected nil for inverted Span, got %v", got)
	}
}

func TestExtLookupNotFound(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.ExtString("nonexistent"); ok {
		t.Error("expected not found")
	}
	if _, ok := e.Ext([]byte("nonexistent")); ok {
		t.Error("expected not found")
	}
}

func TestExtNilRaw(t *testing.T) {
	e := &Event{}
	if _, ok := e.Ext([]byte("src")); ok {
		t.Error("expected false for nil-raw Ext")
	}
	if _, ok := e.ExtString("src"); ok {
		t.Error("expected false for nil-raw ExtString")
	}
}

const keySrc = "src"

func TestExtCount(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`))
	if err != nil {
		t.Fatal(err)
	}
	if e.ExtCount != 2 {
		t.Fatalf("expected 2, got %d", e.ExtCount)
	}
	p, ok := e.ExtAt(0)
	if !ok || e.Text(p.Key) != keySrc {
		t.Errorf("first key: got %q, want src", e.Text(p.Key))
	}
}

func TestExtCountEmpty(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|`))
	if err != nil {
		t.Fatal(err)
	}
	if e.ExtCount != 0 {
		t.Fatalf("expected 0, got %d", e.ExtCount)
	}
}

func TestExtAt(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`))
	if err != nil {
		t.Fatal(err)
	}

	p, ok := e.ExtAt(0)
	if !ok {
		t.Fatal("ExtAt(0): expected ok")
	}
	if e.Text(p.Key) != "src" {
		t.Errorf("ExtAt(0).Key: got %q, want src", e.Text(p.Key))
	}
	p, ok = e.ExtAt(1)
	if !ok {
		t.Fatal("ExtAt(1): expected ok")
	}
	if e.Text(p.Key) != "dst" {
		t.Errorf("ExtAt(1).Key: got %q, want dst", e.Text(p.Key))
	}
	if _, ok = e.ExtAt(2); ok {
		t.Error("ExtAt(2): expected not ok")
	}
	if _, ok = e.ExtAt(-1); ok {
		t.Error("ExtAt(-1): expected not ok")
	}
}

func TestExtAtEmpty(t *testing.T) {
	e := &Event{}
	if _, ok := e.ExtAt(0); ok {
		t.Error("ExtAt on empty event: expected not ok")
	}
}

func TestAllIterator(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2 msg=hello`))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k, v := range e.All() {
		keys = append(keys, e.Text(k))
		_ = v
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "src" || keys[1] != "dst" || keys[2] != "msg" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestAllIteratorBreakEarly(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2 msg=hello`))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range e.All() {
		count++
		if count == 1 {
			break
		}
	}
	if count != 1 {
		t.Errorf("expected 1 iteration before break, got %d", count)
	}
}

func TestUsedRangeExtensionsOnly(t *testing.T) {
	e := &Event{
		raw:      []byte("key=value"),
		ExtCount: 1,
	}
	e.extKeys[0] = Span{0, 3}
	e.extVals[0] = Span{4, 9}
	lo, hi := e.usedRange()
	if lo != 0 || hi != 9 {
		t.Errorf("usedRange: got [%d, %d), want [0, 9)", lo, hi)
	}
}

// ---------------------------------------------------------------------------
// Event.String()
// ---------------------------------------------------------------------------

func TestEventString(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|src=1.2.3.4`))
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	for _, want := range []string{"Cisco", "ver=0", "exts=1", "devver=4.0", "classid=100"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q: %s", want, s)
		}
	}
}

func TestEventStringNil(t *testing.T) {
	e := &Event{}
	if s := e.String(); s != "Event{}" {
		t.Errorf("expected Event{}, got %q", s)
	}
}

func TestStringWithExtensions(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`))
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	if !strings.Contains(s, "src=1.2.3.4") {
		t.Errorf("String() should contain extension sample, got: %s", s)
	}
}

func TestStringTruncatesLongValues(t *testing.T) {
	m := NewParser()
	longVal := strings.Repeat("x", 50)
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=` + longVal)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	if strings.Contains(s, longVal) {
		t.Error("String() should truncate long values")
	}
	if !strings.Contains(s, "...") {
		t.Error("String() should contain '...' for truncated values")
	}
}

func TestStringManyExtensions(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|a=1 b=2 c=3 d=4 e=5`))
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	if !strings.Contains(s, " ...") {
		t.Errorf("String() with >3 exts should contain ' ...' ellipsis, got: %s", s)
	}
}

// ---------------------------------------------------------------------------
// Version.String()
// ---------------------------------------------------------------------------

func TestVersionStringFastPath(t *testing.T) {
	allocs0 := testing.AllocsPerRun(100, func() { _ = Version(0).String() })
	if allocs0 > 0 {
		t.Errorf("Version(0).String(): expected 0 allocs, got %f", allocs0)
	}
	allocs1 := testing.AllocsPerRun(100, func() { _ = Version(1).String() })
	if allocs1 > 0 {
		t.Errorf("Version(1).String(): expected 0 allocs, got %f", allocs1)
	}
	if Version(0).String() != "0" {
		t.Errorf("Version(0).String() = %q", Version(0).String())
	}
	if Version(1).String() != "1" {
		t.Errorf("Version(1).String() = %q", Version(1).String())
	}
	if Version(99).String() != "99" {
		t.Errorf("Version(99).String() = %q", Version(99).String())
	}
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

func TestReset(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4`))
	if err != nil {
		t.Fatal(err)
	}
	saved := e.Clone()
	saved.Reset()
	if saved.raw != nil {
		t.Error("Reset: raw should be nil")
	}
	if saved.Version != InvalidVersion {
		t.Error("Reset: Version should be InvalidVersion")
	}
	if saved.ExtCount != 0 {
		t.Error("Reset: ExtCount should be 0")
	}
	if saved.Valid() {
		t.Error("Reset: Valid() should return false")
	}
}

// ---------------------------------------------------------------------------
// Clone & CloneTo
// ---------------------------------------------------------------------------

func TestClone(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`))
	if err != nil {
		t.Fatal(err)
	}
	c := e.Clone()
	if c.Version != e.Version {
		t.Errorf("clone version: got %d, want %d", c.Version, e.Version)
	}
	if c.Text(c.Vendor) != e.Text(e.Vendor) {
		t.Error("clone vendor mismatch")
	}
	if c.ExtCount != e.ExtCount {
		t.Errorf("clone ext count: got %d, want %d", c.ExtCount, e.ExtCount)
	}
	assertExt(t, c, "src", "1.2.3.4")
	assertExt(t, c, "dst", "2.2.2.2")
	_, err = m.Parse([]byte(`CEF:0|X|Y|2|200|Z|9|a=b`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Text(c.Vendor) != "V" {
		t.Error("clone was affected by subsequent parse")
	}
}

func TestCloneIndependence(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4`))
	if err != nil {
		t.Fatal(err)
	}
	c := e.Clone()
	_, err = m.Parse([]byte(`CEF:0|X|Y|2|200|Z|9|dst=9.9.9.9`))
	if err != nil {
		t.Fatal(err)
	}
	assertSpan(t, c, c.Vendor, "V")
	assertExt(t, c, "src", "1.2.3.4")
}

func TestCloneCompactValues(t *testing.T) {
	padding := strings.Repeat("x", 1000)
	input := []byte(`CEF:0|V|P|1|100|` + padding + `|5|src=1.2.3.4`)
	m := NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	c := e.Clone()
	assertSpan(t, c, c.Vendor, "V")
	assertSpan(t, c, c.Product, "P")
	assertSpan(t, c, c.Name, padding)
	assertExt(t, c, "src", "1.2.3.4")
	if len(c.raw) >= len(e.raw) {
		t.Errorf("clone raw should be compact: clone=%d, original=%d", len(c.raw), len(e.raw))
	}
}

func TestCloneNilRaw(t *testing.T) {
	e := &Event{}
	c := e.Clone()
	if c.raw != nil {
		t.Error("expected nil raw in clone of empty event")
	}
}

func TestCloneTo(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|Cisco|ASA|9.16|430003|ACL deny|7|src=10.0.0.1 dst=2.1.2.2 act=Deny`))
	if err != nil {
		t.Fatal(err)
	}
	dst := &Event{}
	result := e.CloneTo(dst)
	if result != dst {
		t.Error("CloneTo should return dst")
	}
	assertSpan(t, dst, dst.Vendor, "Cisco")
	assertSpan(t, dst, dst.Product, "ASA")
	assertExt(t, dst, "src", "10.0.0.1")
	assertExt(t, dst, "act", "Deny")
}

func TestCloneToReusesBuffer(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`))
	if err != nil {
		t.Fatal(err)
	}
	dst := &Event{raw: make([]byte, 0, 4096)}
	e.CloneTo(dst)
	if cap(dst.raw) != 4096 {
		t.Errorf("expected reused buffer cap=4096, got %d", cap(dst.raw))
	}
	assertSpan(t, dst, dst.Vendor, "V")
	assertExt(t, dst, "src", "1.2.3.4")
}

func TestCloneToNilRaw(t *testing.T) {
	e := &Event{}
	dst := &Event{}
	e.CloneTo(dst)
	if dst.raw != nil {
		t.Error("expected nil raw in CloneTo of empty event")
	}
}

func TestCloneToZeroAlloc(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	dst := &Event{raw: make([]byte, 0, 256)}
	e.CloneTo(dst)
	allocs := testing.AllocsPerRun(100, func() { e.CloneTo(dst) })
	if allocs > 0 {
		t.Errorf("expected 0 allocs after warmup, got %f", allocs)
	}
}

// assertSpansEmpty checks that all given spans are empty.
func assertSpansEmpty(t *testing.T, spans map[string]Span) {
	t.Helper()
	for name, s := range spans {
		if !s.IsEmpty() {
			t.Errorf("%s should be empty, got %s", name, s)
		}
	}
}

func TestCloneBestEffortPartialHeader(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte(`CEF:0|Vendor|Product`))
	if err == nil {
		t.Fatal("expected error")
	}
	if e == nil {
		t.Fatal("expected non-nil event in best-effort mode")
	}
	c := e.Clone()
	if c == nil {
		t.Fatal("Clone returned nil")
	}
	assertSpan(t, c, c.Vendor, "Vendor")
	assertSpan(t, c, c.Product, "Product")
	assertSpansEmpty(t, map[string]Span{
		"DevVersion": c.DevVersion,
		"ClassID":    c.ClassID,
		"Name":       c.Name,
		"Severity":   c.Severity,
	})
	if got := c.Text(c.DevVersion); got != "" {
		t.Errorf("DevVersion text: got %q, want empty", got)
	}
	if got, ok := c.SeverityNum(); got != 0 || ok {
		t.Errorf("SeverityNum: got (%d, %v), want (0, false)", got, ok)
	}
	b, err := c.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if b == nil {
		t.Fatal("MarshalText returned nil")
	}
}

func TestCloneToBestEffortPartialHeader(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte(`CEF:0|Vendor|Product`))
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
	if e == nil {
		t.Fatal("expected non-nil event in best-effort mode")
	}
	dst := &Event{raw: make([]byte, 0, 256)}
	e.CloneTo(dst)
	assertSpan(t, dst, dst.Vendor, "Vendor")
	if !dst.DevVersion.IsEmpty() {
		t.Errorf("DevVersion should be empty, got %s", dst.DevVersion)
	}
}

func TestCloneRebaseZeroOffset(t *testing.T) {
	e := &Event{
		raw:            []byte("CEF:0|V|P|1|100|N|5|"),
		Version:        0,
		Vendor:         Span{0, 3},
		Product:        Span{4, 5},
		DevVersion:     Span{6, 7},
		ClassID:        Span{8, 11},
		Name:           Span{12, 13},
		Severity:       Span{14, 15},
		headerComplete: true,
	}
	e.rebase(0)
	if e.Vendor != (Span{0, 3}) {
		t.Errorf("expected unchanged span, got %s", e.Vendor)
	}
}

// ---------------------------------------------------------------------------
// UnmarshalText / MarshalText
// ---------------------------------------------------------------------------

func TestUnmarshalText(t *testing.T) {
	input := []byte(`CEF:0|Security|ThreatManager|1.0|100|worm stopped|10|src=10.0.0.1`)
	var e Event
	if err := e.UnmarshalText(input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Valid() {
		t.Fatal("expected valid event")
	}
	assertSpan(t, &e, e.Vendor, "Security")
	assertExt(t, &e, "src", "10.0.0.1")
}

func TestUnmarshalTextError(t *testing.T) {
	var e Event
	if err := e.UnmarshalText([]byte(`NOT CEF`)); err == nil {
		t.Fatal("expected error for invalid CEF")
	}
}

func TestUnmarshalTextEmpty(t *testing.T) {
	var e Event
	err := e.UnmarshalText([]byte{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnmarshalTextIndependentOfInput(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4`)
	var e Event
	if err := e.UnmarshalText(input); err != nil {
		t.Fatal(err)
	}
	copy(input, "XXXXXXXXXXXXXXXXXXXXXXXXXX")
	assertSpan(t, &e, e.Vendor, "V")
	assertExt(t, &e, "src", "1.2.3.4")
}

func TestUnescapeHeaderWithDstBuffer(t *testing.T) {
	raw := []byte(`test \| value`)
	dst := make([]byte, 0, 64)
	got := UnescapeHeader(raw, dst)
	if string(got) != "test | value" {
		t.Errorf("got %q, want %q", got, "test | value")
	}
}

func TestMarshalText(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|Security|ThreatManager|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.MarshalText()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("MarshalText:\n got: %s\nwant: %s", got, input)
	}
}

func TestMarshalTextHeaderOnly(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `CEF:0|V|P|1|100|N|5|` {
		t.Errorf("got %q", got)
	}
}

func TestMarshalTextNilEvent(t *testing.T) {
	e := &Event{}
	got, err := e.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil, got %q", got)
	}
}

func TestMarshalTextNoTrailingPipe(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `CEF:0|V|P|1|100|N|5|` {
		t.Errorf("got %q", got)
	}
}

func TestMarshalTextEscapesPreserved(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|security|threatmanager|1.0|100|detected a \| in message|10|msg=equation is 2+2\=4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("MarshalText:\n got: %s\nwant: %s", got, input)
	}
}

func TestMarshalTextRoundTrip(t *testing.T) {
	inputs := []string{
		`CEF:0|Security|ThreatManager|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2`,
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|CiscoCVAlertType=Intrusion src=192.168.1.100`,
		`CEF:0|Check Point|NGFW|R81.20|25000|Accept|3|src=10.0.0.100 dst=8.8.8.8 cp_severity=Low`,
		`CEF:0|V|P|1|100|N|5|msg=hello world src=1.2.3.4`,
		`CEF:0|V|P|1|100|N|5|`,
		`CEF:0||||||5|`,
		`CEF:1|Vendor|Product|1.0|100|Name|5|`,
	}
	m := NewParser()
	for _, in := range inputs {
		name := in
		if len(name) > 40 {
			name = name[:40]
		}
		t.Run(name, func(t *testing.T) {
			e, err := m.Parse([]byte(in))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := e.MarshalText()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			e2, err := m.Parse(got)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if e2.Text(e2.Vendor) != e.Text(e.Vendor) {
				t.Errorf("vendor: got %q, want %q", e2.Text(e2.Vendor), e.Text(e.Vendor))
			}
			if e2.ExtCount != e.ExtCount {
				t.Errorf("ext count: got %d, want %d", e2.ExtCount, e.ExtCount)
			}
		})
	}
}

func TestMarshalTextCloned(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`))
	if err != nil {
		t.Fatal(err)
	}
	c := e.Clone()
	got, err := c.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	want := `CEF:0|V|P|1|100|N|5|src=1.2.3.4 dst=2.2.2.2`
	if string(got) != want {
		t.Errorf("MarshalText after Clone:\n got: %s\nwant: %s", got, want)
	}
}

func TestVersionDigitsAllBranches(t *testing.T) {
	tests := []struct {
		v    Version
		want int
	}{
		{0, 1}, {9, 1}, // v < 10
		{10, 2}, {99, 2}, // v < 100
		{100, 3}, {999, 3}, // v < 1000
		{1000, 4}, // v >= 1000
	}
	for _, tt := range tests {
		got := versionDigits(tt.v)
		if got != tt.want {
			t.Errorf("versionDigits(%d) = %d, want %d", tt.v, got, tt.want)
		}
	}
}

func TestAppendBytesInvalidSpan(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|`))
	if err != nil {
		t.Fatal(err)
	}

	// Inverted span (Start > End) — must return dst unchanged.
	dst := []byte("prefix")
	got := e.AppendBytes(dst, Span{Start: 10, End: 5})
	if string(got) != "prefix" {
		t.Errorf("inverted span: got %q, want %q", got, "prefix")
	}

	// Out-of-bounds span — must return dst unchanged.
	got = e.AppendBytes(dst, Span{Start: 0, End: 99999})
	if string(got) != "prefix" {
		t.Errorf("out-of-bounds span: got %q, want %q", got, "prefix")
	}

	// Nil raw — must return dst unchanged.
	var empty Event
	got = empty.AppendBytes(dst, Span{Start: 0, End: 5})
	if string(got) != "prefix" {
		t.Errorf("nil raw: got %q, want %q", got, "prefix")
	}
}

func TestMarshalTextHighVersion(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:99|V|P|1|100|N|5|src=1.2.3.4`))
	if err != nil {
		t.Fatal(err)
	}
	got, merr := e.MarshalText()
	if merr != nil {
		t.Fatal(merr)
	}
	want := `CEF:99|V|P|1|100|N|5|src=1.2.3.4`
	if string(got) != want {
		t.Errorf("MarshalText(CEF:99):\n got: %s\nwant: %s", got, want)
	}
	e2, err := m.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Version != 99 {
		t.Errorf("version after round-trip: got %d, want 99", e2.Version)
	}
}
