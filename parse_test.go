package cef

import (
	"strings"
	"testing"
)

func TestParseMinimal(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Valid() {
		t.Fatal("expected valid message")
	}
	if e.Version != 0 {
		t.Errorf("version: got %d, want 0", e.Version)
	}
	assertSpan(t, e, e.Vendor, "Cisco")
	assertSpan(t, e, e.Product, "CyberVision")
	assertSpan(t, e, e.DevVersion, "4.0")
	assertSpan(t, e, e.ClassID, "100")
	assertSpan(t, e, e.Name, "Alert")
	assertSpan(t, e, e.Severity, "5")
	if e.ExtCount != 0 {
		t.Errorf("ext count: got %d, want 0", e.ExtCount)
	}
}

func TestParseWithExtensions(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|Security|ThreatManager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount != 3 {
		t.Fatalf("ext count: got %d, want 3", e.ExtCount)
	}
	assertExt(t, e, "src", "10.0.0.1")
	assertExt(t, e, "dst", "2.1.2.2")
	assertExt(t, e, "spt", "1232")
}

func TestParseNoTrailingPipe(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|Vendor|Product|1.0|100|Name|5`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Valid() {
		t.Fatal("expected valid message")
	}
	assertSpan(t, e, e.Severity, "5")
}

func TestParseVersion1(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:1|Vendor|Product|1.0|100|Name|5|`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Version != 1 {
		t.Errorf("version: got %d, want 1", e.Version)
	}
}

func TestParseVersion2Future(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:2|Vendor|Product|1.0|100|Name|5|`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Version != 2 {
		t.Errorf("version: got %d, want 2", e.Version)
	}
}

func TestParseSpaceAfterPrefix(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF: 0|Barracuda|WAAS|1.0|WAF|WAF|4|src=1.2.3.4`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Version != 0 {
		t.Errorf("version: got %d, want 0", e.Version)
	}
	assertSpan(t, e, e.Vendor, "Barracuda")
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParseMultipleSpacesAfterPrefix(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:   1|V|P|1.0|100|N|5|`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Version != 1 {
		t.Errorf("version: got %d, want 1", e.Version)
	}
}

func TestParseEmptyFields(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0||prod||classid||5|`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Valid() {
		t.Fatal("expected valid message")
	}
	assertSpan(t, e, e.Vendor, "")
	assertSpan(t, e, e.Product, "prod")
	assertSpan(t, e, e.DevVersion, "")
	assertSpan(t, e, e.ClassID, "classid")
	assertSpan(t, e, e.Name, "")
	assertSpan(t, e, e.Severity, "5")
}

func TestParseEmptyInput(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte{})
	if err == nil {
		t.Fatal("expected error")
	}
	if e != nil {
		t.Fatal("expected nil message")
	}
}

func TestParseEmptyInputBestEffort(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte{})
	if err == nil {
		t.Fatal("expected error")
	}
	if e == nil {
		t.Fatal("expected non-nil message in best effort")
	}
}

func TestParseInvalidPrefix(t *testing.T) {
	m := NewParser()
	_, err := m.Parse([]byte(`NOTCEF:0|a|b|c|d|e|5|`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseTruncatedHeader(t *testing.T) {
	m := NewParser()
	_, err := m.Parse([]byte(`CEF:0|Vendor|Product`))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestParseTruncatedHeaderBestEffort(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte(`CEF:0|Vendor|Product`))
	if err == nil {
		t.Fatal("expected error")
	}
	if e.Version != 0 {
		t.Errorf("version: got %d, want 0", e.Version)
	}
	assertSpan(t, e, e.Vendor, "Vendor")
}

func TestParseValueWithSpaces(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=hello world src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "hello world")
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParseValueWithEquals(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=hello\=world src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", `hello\=world`)
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParsePipeInExtensionValue(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|act=blocked a | dst=1.1.1.1`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "act", "blocked a |")
	assertExt(t, e, "dst", "1.1.1.1")
}

func TestParseTrailingSpacesLastValue(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4   `)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParseVendorCustomKeys(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|CiscoCVDeviceIP=10.0.0.1 cp_severity=High`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "CiscoCVDeviceIP", "10.0.0.1")
	assertExt(t, e, "cp_severity", "High")
}

func TestParseKeyWithSpecialChars(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|key.with-dash_under[0]=value`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "key.with-dash_under[0]", "value")
}

func TestParseLargeBuffer(t *testing.T) {
	m := NewParser()
	val := strings.Repeat("x", 70000)
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=` + val)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	span, ok := e.ExtString("msg")
	if !ok {
		t.Fatal("expected ext msg")
	}
	if span.Len() != 70000 {
		t.Errorf("value length: got %d, want 70000", span.Len())
	}
}

func TestParseMaxExtensions(t *testing.T) {
	m := NewParser()
	parts := make([]string, 0, MaxExtensions)
	for i := 0; i < MaxExtensions; i++ {
		parts = append(parts, "k"+string(rune('A'+i/26))+string(rune('a'+i%26))+"=v")
	}
	input := []byte(`CEF:0|V|P|1|100|N|5|` + strings.Join(parts, " "))
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount != MaxExtensions {
		t.Errorf("ext count: got %d, want %d", e.ExtCount, MaxExtensions)
	}
}

func TestParseWithMaxExtensionsOption(t *testing.T) {
	m := NewParser(WithMaxExtensions(2))
	input := []byte(`CEF:0|V|P|1|100|N|5|a=1 b=2 c=3`)
	_, err := m.Parse(input)
	if err == nil {
		t.Fatal("expected error when exceeding max extensions without BestEffort")
	}
}

func TestParseWithMaxExtensionsBestEffort(t *testing.T) {
	m := NewParser(WithBestEffort(), WithMaxExtensions(2))
	input := []byte(`CEF:0|V|P|1|100|N|5|a=1 b=2 c=3`)
	e, err := m.Parse(input)
	if e == nil {
		t.Fatal("expected non-nil message")
	}
	_ = err
	if e.ExtCount != 2 {
		t.Errorf("ext count: got %d, want 2", e.ExtCount)
	}
}

func TestParseUTF8Values(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=héllo wörld src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "héllo wörld")
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParseParserReuse(t *testing.T) {
	m := NewParser()
	inputs := [][]byte{
		[]byte(`CEF:0|V1|P1|1|100|N1|5|src=1.1.1.1`),
		[]byte(`CEF:1|V2|P2|2|200|N2|8|dst=2.2.2.2`),
	}
	for _, input := range inputs {
		e, err := m.Parse(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !e.Valid() {
			t.Fatal("expected valid message")
		}
	}
	e, err := m.Parse(inputs[1])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Version != 1 {
		t.Errorf("version: got %d, want 1", e.Version)
	}
	assertSpan(t, e, e.Vendor, "V2")
}

func TestParseMultilineValue(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=line1\nline2 src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", `line1\nline2`)
}

func TestParseBackslashInValue(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=hello\\world src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", `hello\\world`)
}

func TestParseDoubleBackslashBeforeEquals(t *testing.T) {
	m := NewParser()
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=test\\=notkey src=1.2.3.4`)
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount != 2 {
		t.Fatalf("ext count: got %d, want 2", e.ExtCount)
	}
}

func TestParseOnlyPrefix(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte(`CEF:`))
	if err == nil {
		t.Fatal("expected error")
	}
	if e.Version != -1 {
		t.Errorf("version: got %d, want -1", e.Version)
	}
}

func TestParseExtensionsLeadingSpaces(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|   src=1.2.3.4`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParseExtKeyInvalidBestEffort(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte("CEF:0|V|P|1|100|N|5|bad key=val"))
	_ = err // best-effort: error expected for invalid key
	if e == nil {
		t.Fatal("expected non-nil event")
	}
}

func TestParseExtensionsNoEquals(t *testing.T) {
	m := NewParser()
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|thisisjusttext`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount != 0 {
		t.Errorf("expected 0 extensions, got %d", e.ExtCount)
	}
}

func TestParseVersionFiveDigits(t *testing.T) {
	m := NewParser()
	_, err := m.Parse([]byte(`CEF:99999|V|P|1|100|N|5|`))
	if err == nil {
		t.Fatal("expected ErrVersion")
	}
}

func TestParseVersionFiveDigitsBestEffort(t *testing.T) {
	m := NewParser(WithBestEffort())
	e, err := m.Parse([]byte(`CEF:99999|V|P|1|100|N|5|`))
	if err == nil {
		t.Fatal("expected ErrVersion")
	}
	if e == nil {
		t.Fatal("expected non-nil event in best-effort mode")
	}
	if e.Version != -1 {
		t.Errorf("version: got %d, want -1", e.Version)
	}
}

func TestParseParserReuseAfterError(t *testing.T) {
	m := NewParser()
	_, err := m.Parse([]byte(`CEF:0|Vendor|Product`))
	if err == nil {
		t.Fatal("expected error on truncated input")
	}
	e, err := m.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=1.2.3.4`))
	if err != nil {
		t.Fatalf("unexpected error after reuse: %v", err)
	}
	if !e.Valid() {
		t.Fatal("expected valid message")
	}
	assertExt(t, e, "src", "1.2.3.4")
}

func TestParseVersionBytes(t *testing.T) {
	tests := []struct {
		input string
		want  Version
	}{
		{"0", 0}, {"1", 1}, {"9", 9}, {"10", 10}, {"25", 25},
		{"999", 999}, {"9999", 9999}, {"12345", -1}, {"99999", -1},
	}
	for _, tt := range tests {
		got := parseVersionBytes([]byte(tt.input))
		if got != tt.want {
			t.Errorf("parseVersionBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseString(t *testing.T) {
	m := NewParser()

	// Normal input.
	e, err := m.ParseString(`CEF:0|Vendor|Product|1.0|100|Name|5|src=1.2.3.4`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Vendor, "Vendor")
	assertExt(t, e, "src", "1.2.3.4")

	// Empty string.
	_, err = m.ParseString("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}
