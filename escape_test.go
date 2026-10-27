package cef

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// fieldText is a named string type, which the escapers take as they take a string.
type fieldText string

func TestAppendEscapedHeaderEscapes(t *testing.T) {
	for _, tc := range []struct{ field, want string }{
		{testMsgHelloWorld, testMsgHelloWorld},
		{"a|b", `a\|b`},
		{`a\b`, `a\\b`},
		{"one\ntwo\rthree", "one two three"},
		{"a=b", "a=b"},
		{"", ""},
	} {
		if got := AppendEscapedHeader(nil, tc.field); string(got) != tc.want {
			t.Errorf("AppendEscapedHeader(%q) = %q, want %q", tc.field, got, tc.want)
		}
		if got := AppendEscapedHeader([]byte("x"), []byte(tc.field)); string(got) != "x"+tc.want {
			t.Errorf("AppendEscapedHeader(x, []byte(%q)) = %q, want %q", tc.field, got, "x"+tc.want)
		}
		if got := AppendEscapedHeader(nil, fieldText(tc.field)); string(got) != tc.want {
			t.Errorf("AppendEscapedHeader(fieldText(%q)) = %q, want %q", tc.field, got, tc.want)
		}
	}
}

func TestAppendEscapedExtValueEscapes(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{testMsgHelloWorld, testMsgHelloWorld},
		{"a=b", `a\=b`},
		{`a\b`, `a\\b`},
		{"one\ntwo\rthree", `one\ntwo\rthree`},
		{"a|b", "a|b"},
		{"", ""},
	} {
		if got := AppendEscapedExtValue(nil, tc.value); string(got) != tc.want {
			t.Errorf("AppendEscapedExtValue(%q) = %q, want %q", tc.value, got, tc.want)
		}
		if got := AppendEscapedExtValue(nil, []byte(tc.value)); string(got) != tc.want {
			t.Errorf("AppendEscapedExtValue([]byte(%q)) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// escapeTexts returns "" and texts of 1 to 17 bytes, each one byte among fillers at
// each place: every byte a field or a value escapes, and bytes beside them.
func escapeTexts() []string {
	texts := []string{""}
	for n := 1; n <= 17; n++ {
		for k := range n {
			for _, fill := range []byte("az0 \x7f\xff") {
				for _, c := range []byte("\\|=\r\n\x00\t\x1f !~\x80\xa0") {
					b := bytes.Repeat([]byte{fill}, n)
					b[k] = c
					texts = append(texts, string(b))
				}
			}
		}
	}
	return texts
}

func TestAppendEscapedHeaderMarksEachLane(t *testing.T) {
	for _, s := range escapeTexts() {
		want := refEscapeHeader(s)
		if got := AppendEscapedHeader(nil, s); string(got) != want {
			t.Fatalf("AppendEscapedHeader(%q) = %q, want %q", s, got, want)
		}
		if got := AppendEscapedHeader(nil, []byte(s)); string(got) != want {
			t.Fatalf("AppendEscapedHeader([]byte(%q)) = %q, want %q", s, got, want)
		}
	}
}

func TestAppendEscapedExtValueMarksEachLane(t *testing.T) {
	for _, s := range escapeTexts() {
		want := refEscapeValue(s)
		if got := AppendEscapedExtValue(nil, s); string(got) != want {
			t.Fatalf("AppendEscapedExtValue(%q) = %q, want %q", s, got, want)
		}
		if got := AppendEscapedExtValue(nil, []byte(s)); string(got) != want {
			t.Fatalf("AppendEscapedExtValue([]byte(%q)) = %q, want %q", s, got, want)
		}
	}
}

func TestValidKeyBytes(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"src", true},
		{"cs1Label", true},
		{"ad.foo-bar_baz[0]", true},
		{strings.Repeat("k", 300), true},
		{"", false},
		{"bad key", false},
		{"a=b", false},
		{"a\\b", false},
		{"a:b", false},
		{"é", false},
	} {
		if got := ValidKey(tc.key); got != tc.want {
			t.Errorf("ValidKey(%q) = %t, want %t", tc.key, got, tc.want)
		}
		if got := ValidKey([]byte(tc.key)); got != tc.want {
			t.Errorf("ValidKey([]byte(%q)) = %t, want %t", tc.key, got, tc.want)
		}
	}
	for c := range 256 {
		want := strings.IndexByte(refKeyBytes, byte(c)) >= 0
		if got := ValidKey([]byte{byte(c)}); got != want {
			t.Errorf("ValidKey(%q) = %t, want %t", byte(c), got, want)
		}
	}
}

func TestAppendEscapedHeaderAllocs(t *testing.T) {
	dst := make([]byte, 0, 128)
	field, value := "a|b\\c\nd", "a=b\\c\nd"
	longField, longValue := "Palo Alto | PAN-OS \\ fw\r\nx", "Palo Alto = PAN-OS \\ fw\r\nx"
	assertAllocs(t, 0, func() { _ = AppendEscapedHeader(dst, field) })
	assertAllocs(t, 0, func() { _ = AppendEscapedExtValue(dst, value) })
	assertAllocs(t, 0, func() { _ = AppendEscapedHeader(dst, longField) })
	assertAllocs(t, 0, func() { _ = AppendEscapedExtValue(dst, longValue) })
	assertAllocs(t, 0, func() { _ = ValidKey(field) })
}

func TestAppendEscapedHeaderCostIsLinear(t *testing.T) {
	assertEncodeCost(t, "AppendEscapedHeader", AppendEscapedHeader[string], []string{"|", "\\\n", "a", "ab|c "})
}

func TestAppendEscapedExtValueCostIsLinear(t *testing.T) {
	assertEncodeCost(t, "AppendEscapedExtValue", AppendEscapedExtValue[string], []string{"=", "\\\r", "a", "ab=c "})
}

// assertEncodeCost fails t unless encode, named name, escapes 4096 and 4096*costScale
// copies of each of units at a cost linear in their length.
func assertEncodeCost(t *testing.T, name string, encode func(dst []byte, s string) []byte, units []string) {
	t.Helper()
	for _, unit := range units {
		small, large := strings.Repeat(unit, 4096), strings.Repeat(unit, 4096*costScale)
		dst := make([]byte, 0, 2*len(large))
		var out []byte
		assertCost(t, func() { out = encode(dst, small) }, func() { out = encode(dst, large) }, costScale)
		if len(out) < len(large) || t.Failed() {
			t.Fatalf("%s(%d x %q) = %d bytes, failed %t, want %d or more and a linear cost",
				name, 4096*costScale, unit, len(out), t.Failed(), len(large))
		}
	}
}

func TestByteClassesMatchTheirSets(t *testing.T) {
	for _, tc := range []struct {
		class byte
		set   string
	}{
		{classKey, refKeyBytes},
		{classHeaderEscape, `|\`},
		{classValueEscape, `=\nr`},
		{classHeaderSpecial, "\\|\r\n"},
		{classValueSpecial, "\\=\r\n"},
		{classTrailing, " \r\n"},
	} {
		for c := range 256 {
			want := strings.IndexByte(tc.set, byte(c)) >= 0
			if got := byteClasses[c]&tc.class != 0; got != want {
				t.Errorf("byte %q in class %#x = %t, want %t", byte(c), tc.class, got, want)
			}
		}
	}
}

// refEscapeHeader returns field escaped by literal replacement: '\' and '|' behind a
// backslash, CR and LF as spaces.
func refEscapeHeader(field string) string {
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "\r", " ", "\n", " ").Replace(field)
}

// refEscapeValue returns value escaped by literal replacement: '\' and '=' behind a
// backslash, CR and LF as \r and \n.
func refEscapeValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, "=", `\=`, "\r", `\r`, "\n", `\n`).Replace(value)
}

func FuzzAppendEscapedHeader(f *testing.F) {
	f.Add("a|b\\c")
	f.Fuzz(func(t *testing.T, field string) {
		got := AppendEscapedHeader(nil, field)
		if want := refEscapeHeader(field); string(got) != want {
			t.Fatalf("AppendEscapedHeader(%q) = %q, want %q", field, got, want)
		}
		want := strings.NewReplacer("\r", " ", "\n", " ").Replace(field)
		if back := UnescapeHeader(got, nil); string(back) != want {
			t.Fatalf("UnescapeHeader(AppendEscapedHeader(%q)) = %q, want %q", field, back, want)
		}
		if fromBytes := AppendEscapedHeader(nil, []byte(field)); !bytes.Equal(fromBytes, got) {
			t.Fatalf("AppendEscapedHeader(nil, []byte(%q)) = %q, want %q", field, fromBytes, got)
		}
	})
}

func FuzzAppendEscapedExtValue(f *testing.F) {
	f.Add("a=b\\c\r\n")
	f.Fuzz(func(t *testing.T, value string) {
		got := AppendEscapedExtValue(nil, value)
		if want := refEscapeValue(value); string(got) != want {
			t.Fatalf("AppendEscapedExtValue(%q) = %q, want %q", value, got, want)
		}
		if back := UnescapeExtValue(got, nil); string(back) != value {
			t.Fatalf("UnescapeExtValue(AppendEscapedExtValue(%q)) = %q, want it back", value, back)
		}
		if bytes.ContainsAny(got, "\r\n") || bytes.Contains(got, []byte(" =")) {
			t.Fatalf("AppendEscapedExtValue(%q) = %q, want no CR, no LF and no \" =\"", value, got)
		}
		if fromBytes := AppendEscapedExtValue(nil, []byte(value)); !bytes.Equal(fromBytes, got) {
			t.Fatalf("AppendEscapedExtValue(nil, []byte(%q)) = %q, want %q", value, fromBytes, got)
		}
	})
}

func FuzzValidKey(f *testing.F) {
	f.Add("cs1Label")
	f.Fuzz(func(t *testing.T, key string) {
		if got, want := ValidKey(key), refIsKey([]byte(key)); got != want {
			t.Fatalf("ValidKey(%q) = %t, want %t", key, got, want)
		}
	})
}

func FuzzAppendEscapedEventParses(f *testing.F) {
	f.Add("Vendor|X", "Product", "msg", "a = b \\ c\nd", "src", "10.0.0.1")
	f.Fuzz(func(t *testing.T, vendor, product, k1, v1, k2, v2 string) {
		if !refIsKey([]byte(k1)) || !refIsKey([]byte(k2)) {
			return
		}
		v2 = strings.TrimRight(v2, " ")
		header := []string{vendor, product, "1.0", "100", "Name", "5"}
		line := []byte("CEF:0|")
		for _, field := range header {
			line = append(AppendEscapedHeader(line, field), '|')
		}
		line = AppendEscapedExtValue(append(append(line, k1...), '='), v1)
		line = AppendEscapedExtValue(append(append(append(line, ' '), k2...), '='), v2)
		var e Event
		if err := e.Parse(line, MaxExtensions); err != nil {
			t.Fatalf("Parse(%q) = %v, want nil", line, err)
		}
		if diff := escapedDiff(&e, header, [][2]string{{k1, v1}, {k2, v2}}); diff != "" {
			t.Fatalf("Parse(%q): %s", line, diff)
		}
	})
}

// escapedDiff returns the first header field or pair of e whose bytes are not the
// literal escapes of the text it was built from, or do not decode back to that text.
func escapedDiff(e *Event, header []string, pairs [][2]string) string {
	spans := [...]Span{e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(), e.Name(),
		e.Severity()}
	oneLine := strings.NewReplacer("\r", " ", "\n", " ")
	for i, field := range header {
		raw := e.Bytes(spans[i])
		if string(raw) != refEscapeHeader(field) || string(UnescapeHeader(raw, nil)) != oneLine.Replace(field) {
			return fmt.Sprintf("header field %d = %q, want %q", i, raw, refEscapeHeader(field))
		}
	}
	for i, kv := range pairs {
		p, ok := e.ExtAt(i)
		raw := e.Bytes(p.Value)
		if !ok || e.Text(p.Key) != kv[0] || string(raw) != refEscapeValue(kv[1]) ||
			string(UnescapeExtValue(raw, nil)) != kv[1] {
			return fmt.Sprintf("pair %d = %q=%q, want %q=%q", i, e.Bytes(p.Key), raw, kv[0], refEscapeValue(kv[1]))
		}
	}
	return ""
}

func BenchmarkAppendEscapedHeader(b *testing.B) {
	benchEscape(b, AppendEscapedHeader[string], refEscapeHeader, "Palo Alto Networks | PAN-OS \\ firewall")
}

func BenchmarkAppendEscapedExtValue(b *testing.B) {
	benchEscape(b, AppendEscapedExtValue[string], refEscapeValue, "https://example.com/path?query=value&other=1\\x")
}

// benchEscape measures f on a clean text and on value, which needs escapes, each result
// first compared with ref's.
func benchEscape(b *testing.B, f func([]byte, string) []byte, ref func(string) string, value string) {
	b.Helper()
	for _, s := range []struct{ name, text string }{
		{"Clean", "Suspicious network activity detected on OT segment"},
		{"Escaped", value},
	} {
		b.Run(s.name, func(b *testing.B) {
			dst := make([]byte, 0, 4*len(s.text))
			if got, want := f(dst, s.text), ref(s.text); string(got) != want {
				b.Fatalf("escaping %q = %q, want %q", s.text, got, want)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(s.text)))
			for b.Loop() {
				_ = f(dst, s.text)
			}
		})
	}
}

func BenchmarkTextWord(b *testing.B) {
	text := strings.Repeat("Palo Alto | PAN-OS \\ fw ", 2)
	for i := 0; i+scanBytes <= len(text); i += scanBytes {
		want := refWord(text, i)
		if got, shared := textWord(text[i:]), sharedWordAt(text, i); got != want || shared != want {
			b.Fatalf("textWord, sharedWordAt(text, %d) = %#x, %#x, want %#x", i, got, shared, want)
		}
	}
	b.Run("Own", func(b *testing.B) {
		out := heapCell[uint64](b)
		b.ReportAllocs()
		b.SetBytes(int64(len(text)))
		for b.Loop() {
			var m uint64
			for i := 0; i+scanBytes <= len(text); i += scanBytes {
				m += escapeLanes(textWord(text[i:]), '|')
			}
			*out = m
		}
	})
	b.Run("SharedForm", func(b *testing.B) {
		out := heapCell[uint64](b)
		b.ReportAllocs()
		b.SetBytes(int64(len(text)))
		for b.Loop() {
			var m uint64
			for i := 0; i+scanBytes <= len(text); i += scanBytes {
				m += escapeLanes(sharedWordAt(text, i), '|')
			}
			*out = m
		}
	})
}

func BenchmarkValidKey(b *testing.B) {
	key := "deviceCustomString1Label"
	if !ValidKey(key) {
		b.Fatalf("ValidKey(%q) = false, want true", key)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = ValidKey(key)
	}
}

func ExampleAppendEscapedExtValue() {
	line := []byte("CEF:0|")
	for _, field := range []string{"Vendor", "Product|X", "1.0", "100", "Name", "5"} {
		line = append(AppendEscapedHeader(line, field), '|')
	}
	line = AppendEscapedExtValue(append(line, "msg="...), "a=b\nc")
	fmt.Println(string(line), ValidKey("msg"))
	// Output: CEF:0|Vendor|Product\|X|1.0|100|Name|5|msg=a\=b\nc true
}
