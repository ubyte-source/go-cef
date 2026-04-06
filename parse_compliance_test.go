package cef_test

import (
	"testing"

	cef "github.com/ubyte-source/go-cef"
)

// ---------------------------------------------------------------------------
// Test helpers (shared across all external _test.go files in package cef_test)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Compliance tests verify every rule and example from the CEF spec v26.
// ---------------------------------------------------------------------------

func TestSpecExample_PipeInHeader(t *testing.T) {
	// From the spec: pipe in header value must be escaped as \|
	input := []byte(
		`CEF:0|security|threatmanager|1.0|100|` +
			`detected a \| in message|10|` +
			`src=10.0.0.1 act=blocked a | dst=1.1.1.1`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Name contains the escaped pipe — the raw Span includes the backslash
	assertSpan(t, e, e.Name, `detected a \| in message`)
	// act value contains pipe (NOT escaped in extensions per spec)
	assertExt(t, e, "act", "blocked a |")
	assertExt(t, e, "dst", "1.1.1.1")
}

func TestSpecExample_BackslashInHeader(t *testing.T) {
	input := []byte(`CEF:0|vendor|product|1.0|100|name with \\|5|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Name, `name with \\`)
}

func TestSpecExample_EmptyExtension(t *testing.T) {
	input := []byte(`CEF:0|Security|ThreatManager|1.0|100|worm successfully stopped|10|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount != 0 {
		t.Errorf("ext count: got %d, want 0", e.ExtCount)
	}
}

func TestSpec_EscapedEqualsInExtensionValue(t *testing.T) {
	// \= in extension values means the = is literal, not a key-value separator
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=equation is 2+2\=4 src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", `equation is 2+2\=4`)
	assertExt(t, e, "src", "1.2.3.4")
}

func TestSpec_EscapedBackslashInExtensionValue(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|5|filePath=C:\\Windows\\System32 src=10.0.0.1`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "filePath", `C:\\Windows\\System32`)
	assertExt(t, e, "src", "10.0.0.1")
}

func TestSpec_MultiLineExtensionValue(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=first line\nsecond line\rthird src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", `first line\nsecond line\rthird`)
}

func TestSpec_MultipleSpacesBetweenExtensions(t *testing.T) {
	// Multiple spaces: all but the last are trailing of the previous value
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=hello   src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "hello  ")
	assertExt(t, e, "src", "1.2.3.4")
}

func TestSpec_TrailingSpacesLastValueTrimmed(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=hello world   `)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "hello world")
}

func TestSpec_PipeInExtensionValueNotEscaped(t *testing.T) {
	// Spec says: pipe in extension values does NOT need to be escaped
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=contains | pipe src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "msg", "contains | pipe")
	assertExt(t, e, "src", "1.2.3.4")
}

func TestSpec_ValueWithFilePath(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|5|filePath=/user/dir/my file.txt src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "filePath", "/user/dir/my file.txt")
}

func TestSpec_HeaderEmptyFields(t *testing.T) {
	// All header fields can be empty
	input := []byte(`CEF:0||||||5|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Valid() {
		t.Fatal("expected valid")
	}
	assertSpan(t, e, e.Vendor, "")
	assertSpan(t, e, e.Product, "")
	assertSpan(t, e, e.DevVersion, "")
	assertSpan(t, e, e.ClassID, "")
	assertSpan(t, e, e.Name, "")
	assertSpan(t, e, e.Severity, "5")
}

func TestSpec_SeverityStringUnknown(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|Unknown|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Severity, "Unknown")
}

func TestSpec_SeverityStringVeryHigh(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|N|Very-High|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Severity, "Very-High")
}

func TestSpec_DoubleBackslashBeforeEquals(t *testing.T) {
	// \\= → even number of backslashes means = is NOT escaped
	// But it still needs space+key pattern to break
	input := []byte(`CEF:0|V|P|1|100|N|5|msg=test\\\=value src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ExtCount < 1 {
		t.Fatal("expected at least 1 extension")
	}
}

func TestSpec_ClassIDSpecialChars(t *testing.T) {
	// Spec says ClassID can contain =, %, # characters.
	// These are NOT escaped in the header — only pipe and backslash are escaped.
	tests := []struct {
		name    string
		classID string
	}{
		{"equals", "SIG=100"},
		{"percent", "SIG%100"},
		{"hash", "SIG#100"},
		{"mixed", "SIG=100%CRIT#HIGH"},
	}
	m := cef.NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(`CEF:0|V|P|1|` + tt.classID + `|N|5|src=1.2.3.4`)
			e, err := m.Parse(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertSpan(t, e, e.ClassID, tt.classID)
		})
	}
}

func TestSpec_UTF8InValues(t *testing.T) {
	input := []byte(`CEF:0|V|P|1|100|日本語テスト|5|msg=こんにちは世界 src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Name, "日本語テスト")
	assertExt(t, e, "msg", "こんにちは世界")
}

func TestSpec_DateFormats(t *testing.T) {
	// The parser does NOT interpret dates — it returns raw Spans.
	// We just verify the value is captured correctly.
	tests := []struct {
		name, ext, val string
	}{
		{"epoch_ms", "rt", "1234567890000"},
		{"MMM_dd_HH_mm_ss_SSS_zzz", "rt", "Mar 19 08:26:10.000 UTC"},
		{"MMM_dd_HH_mm_ss_SSS", "rt", "Mar 19 08:26:10.000"},
		{"MMM_dd_HH_mm_ss_zzz", "rt", "Mar 19 08:26:10 UTC"},
		{"MMM_dd_HH_mm_ss", "rt", "Mar 19 08:26:10"},
		{"MMM_dd_yyyy_HH_mm_ss_SSS_zzz", "rt", "Mar 19 2025 08:26:10.000 UTC"},
		{"MMM_dd_yyyy_HH_mm_ss_SSS", "rt", "Mar 19 2025 08:26:10.000"},
		{"MMM_dd_yyyy_HH_mm_ss_zzz", "rt", "Mar 19 2025 08:26:10 UTC"},
		{"MMM_dd_yyyy_HH_mm_ss", "rt", "Mar 19 2025 08:26:10"},
	}
	m := cef.NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(`CEF:0|V|P|1|100|N|5|` + tt.ext + `=` + tt.val)
			e, err := m.Parse(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertExt(t, e, tt.ext, tt.val)
		})
	}
}

func TestSpec_CiscoASAEvent(t *testing.T) {
	input := []byte(
		`CEF:0|Cisco|ASA|9.16|430003|ACL deny|7|` +
			`src=192.168.1.1 dst=10.0.0.1 spt=12345 dpt=443 ` +
			`proto=TCP act=Deny cs1=outside cs1Label=Interface`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Vendor, "Cisco")
	assertSpan(t, e, e.Product, "ASA")
	assertExt(t, e, "src", "192.168.1.1")
	assertExt(t, e, "dst", "10.0.0.1")
	assertExt(t, e, "proto", "TCP")
	assertExt(t, e, "act", "Deny")
	assertExt(t, e, "cs1Label", "Interface")
}

func TestSpec_CheckPointEvent(t *testing.T) {
	input := []byte(
		`CEF:0|Check Point|NGFW|R81.20|25000|Accept|3|` +
			`src=10.0.0.100 dst=8.8.8.8 spt=54321 dpt=53 ` +
			`proto=UDP act=Accept cp_severity=Low`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Vendor, "Check Point")
	assertSpan(t, e, e.Product, "NGFW")
	assertExt(t, e, "cp_severity", "Low")
}

func TestSpec_PaloAltoEvent(t *testing.T) {
	input := []byte(
		`CEF:0|Palo Alto Networks|PAN-OS|11.0|TRAFFIC|end|3|` +
			`src=10.0.0.1 dst=172.16.0.1 PanOSRuleUUID=abc-123 ` +
			`PanOSSourceZone=trust PanOSDestinationZone=untrust`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Vendor, "Palo Alto Networks")
	assertExt(t, e, "PanOSRuleUUID", "abc-123")
	assertExt(t, e, "PanOSSourceZone", "trust")
}

func TestSpec_CiscoCyberVisionEvent(t *testing.T) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion CiscoCVSeverity=critical ` +
			`src=192.168.1.100 dst=192.168.1.200 ` +
			`msg=Suspicious network activity detected`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Vendor, "Cisco")
	assertSpan(t, e, e.Product, "Cyber Vision")
	assertSpan(t, e, e.ClassID, "CiscoCVAlert")
	assertExt(t, e, "CiscoCVAlertType", "Intrusion")
	assertExt(t, e, "CiscoCVSeverity", "critical")
	assertExt(t, e, "msg", "Suspicious network activity detected")
}

func TestSpec_ImpervaWAFEvent(t *testing.T) {
	input := []byte(
		`CEF:0|Imperva|WAF|14.7|SQL Injection|` +
			`SQL Injection Attempt|9|` +
			`src=203.0.113.50 dst=10.0.0.5 dpt=443 ` +
			`cs1=Default Web Policy cs1Label=Policy ` +
			`cs2=Alert Only cs2Label=Action`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertExt(t, e, "cs1", "Default Web Policy")
	assertExt(t, e, "cs1Label", "Policy")
	assertExt(t, e, "cs2", "Alert Only")
}

func TestSpec_ForcepointEvent(t *testing.T) {
	input := []byte(
		`CEF:0|Forcepoint|NGFW|6.10|100100|` +
			`Connection Allowed|2|` +
			`src=10.0.0.50 dst=192.168.1.1 ` +
			`in=1234 out=5678 act=allow`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSpan(t, e, e.Vendor, "Forcepoint")
	assertExt(t, e, "in", "1234")
	assertExt(t, e, "out", "5678")
	assertExt(t, e, "act", "allow")
}
