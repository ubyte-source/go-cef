package cef

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// severityTable is the severity classification written as literals: the field, and
// the level name, the number and the validity SeverityLevel gives.
func severityTable() []struct {
	field string
	name  string
	num   int
	ok    bool
} {
	return []struct {
		field string
		name  string
		num   int
		ok    bool
	}{
		{"0", "Unknown", 0, true},
		{"1", "Low", 1, true},
		{"2", "Low", 2, true},
		{"3", "Low", 3, true},
		{"4", "Medium", 4, true},
		{"5", "Medium", 5, true},
		{"6", "Medium", 6, true},
		{"7", "High", 7, true},
		{"8", "High", 8, true},
		{"9", "Very-High", 9, true},
		{"10", "Very-High", 10, true},
		{"Unknown", "Unknown", 0, true},
		{"unknown", "Unknown", 0, true},
		{"UNKNOWN", "Unknown", 0, true},
		{"Low", "Low", 3, true},
		{"lOw", "Low", 3, true},
		{"Medium", "Medium", 6, true},
		{"MEDIUM", "Medium", 6, true},
		{"High", "High", 8, true},
		{"high", "High", 8, true},
		{"Very-High", "Very-High", 10, true},
		{"very-high", "Very-High", 10, true},
		{"VERY-HIGH", "Very-High", 10, true},
		{"", "Unknown", 0, false},
		{"x", "Unknown", 0, false},
		{"/", "Unknown", 0, false},
		{":", "Unknown", 0, false},
		{"11", "Unknown", 0, false},
		{"05", "Unknown", 0, false},
		{"-1", "Unknown", 0, false},
		{" 5", "Unknown", 0, false},
		{"5 ", "Unknown", 0, false},
		{"Very High", "Unknown", 0, false},
		{"Very\rHigh", "Unknown", 0, false},
		{"Very-Hig", "Unknown", 0, false},
		{"Unknow", "Unknown", 0, false},
		{"Hig", "Unknown", 0, false},
		{"Lov", "Unknown", 0, false},
		{"Medius", "Unknown", 0, false},
		{"Critical", "Unknown", 0, false},
	}
}

func TestEventSeverityLevelClassifiesTheField(t *testing.T) {
	for _, tc := range severityTable() {
		var e Event
		line := "CEF:0|V|P|1|C|N|" + tc.field + "|"
		if err := e.Parse([]byte(line), MaxExtensions); err != nil {
			t.Fatalf("Parse(%q) = %v, want nil", line, err)
		}
		level, num, ok := e.SeverityLevel()
		if level.String() != tc.name || num != tc.num || ok != tc.ok {
			t.Errorf("SeverityLevel() of %q = %v, %d, %t, want %s, %d, %t",
				tc.field, level, num, ok, tc.name, tc.num, tc.ok)
		}
	}
}

func TestEventSeverityLevelOfTheZeroEvent(t *testing.T) {
	var e Event
	if level, num, ok := e.SeverityLevel(); level != LevelUnknown || num != 0 || ok {
		t.Errorf("SeverityLevel() of the zero Event = %v, %d, %t, want Unknown, 0, false", level, num, ok)
	}
}

func TestLevelStringNames(t *testing.T) {
	for _, tc := range []struct {
		level Level
		want  string
	}{
		{LevelUnknown, "Unknown"},
		{LevelLow, "Low"},
		{LevelMedium, "Medium"},
		{LevelHigh, "High"},
		{LevelVeryHigh, "Very-High"},
		{5, "Level(5)"},
		{255, "Level(255)"},
	} {
		if got := tc.level.String(); got != tc.want {
			t.Errorf("Level(%d).String() = %q, want %q", uint8(tc.level), got, tc.want)
		}
	}
}

func TestLevelConstantsAreOrdered(t *testing.T) {
	for i, l := range []Level{LevelUnknown, LevelLow, LevelMedium, LevelHigh, LevelVeryHigh} {
		if int(l) != i {
			t.Errorf("level %v = %d, want %d", l, l, i)
		}
	}
}

func TestEventSeverityLevelAllocs(t *testing.T) {
	var e Event
	if err := e.Parse([]byte("CEF:0|V|P|1|C|N|Very-High|"), MaxExtensions); err != nil {
		t.Fatalf("Parse = %v, want nil", err)
	}
	assertAllocs(t, 0, func() { _, _, _ = e.SeverityLevel() })
	assertAllocs(t, 0, func() { _ = LevelVeryHigh.String() })
	assertAllocs(t, 1, func() { _ = Level(200).String() })
}

// refSeverityLevel classifies a severity field by the documented table: the level name,
// the number and the validity.
func refSeverityLevel(field string) (name string, num int, ok bool) {
	if n, err := strconv.Atoi(field); err == nil && n >= 0 && n <= 10 && strconv.Itoa(n) == field {
		names := [...]string{"Unknown", "Low", "Low", "Low", "Medium", "Medium", "Medium", "High", "High",
			"Very-High", "Very-High"}
		return names[n], n, true
	}
	for _, named := range []struct {
		name string
		num  int
	}{{"Unknown", 0}, {"Low", 3}, {"Medium", 6}, {"High", 8}, {"Very-High", 10}} {
		if strings.EqualFold(field, named.name) && isASCII(field) {
			return named.name, named.num, true
		}
	}
	return "Unknown", 0, false
}

// isASCII reports whether s holds only ASCII bytes.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func FuzzEventSeverityLevel(f *testing.F) {
	for _, tc := range severityTable() {
		f.Add(tc.field)
	}
	f.Fuzz(func(t *testing.T, field string) {
		if strings.ContainsAny(field, `|\`) {
			return
		}
		var e Event
		line := "CEF:0|V|P|1|C|N|" + field + "|"
		if err := e.Parse([]byte(line), MaxExtensions); err != nil {
			t.Fatalf("Parse(%q) = %v, want nil", line, err)
		}
		level, num, ok := e.SeverityLevel()
		name, wantNum, wantOK := refSeverityLevel(field)
		if level.String() != name || num != wantNum || ok != wantOK {
			t.Fatalf("SeverityLevel() of %q = %v, %d, %t, want %s, %d, %t",
				field, level, num, ok, name, wantNum, wantOK)
		}
	})
}

func FuzzLevelString(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(9))
	f.Fuzz(func(t *testing.T, n uint8) {
		names := [...]string{"Unknown", "Low", "Medium", "High", "Very-High"}
		want := "Level(" + strconv.Itoa(int(n)) + ")"
		if int(n) < len(names) {
			want = names[n]
		}
		if got := Level(n).String(); got != want {
			t.Fatalf("Level(%d).String() = %q, want %q", n, got, want)
		}
	})
}

func BenchmarkEventSeverityLevel(b *testing.B) {
	for _, field := range []string{"7", "0", "High", "Very-High", "bogus"} {
		b.Run(field, func(b *testing.B) {
			var e Event
			if err := e.Parse([]byte("CEF:0|V|P|1|C|N|"+field+"|"), MaxExtensions); err != nil {
				b.Fatalf("Parse = %v, want nil", err)
			}
			name, num, ok := refSeverityLevel(field)
			if level, n, valid := e.SeverityLevel(); level.String() != name || n != num || valid != ok {
				b.Fatalf("SeverityLevel() = %v, %d, %t, want %s, %d, %t", level, n, valid, name, num, ok)
			}
			b.ReportAllocs()
			for b.Loop() {
				_, _, _ = e.SeverityLevel()
			}
		})
	}
}

func BenchmarkLevelString(b *testing.B) {
	if LevelVeryHigh.String() != "Very-High" {
		b.Fatalf("LevelVeryHigh.String() = %q, want %q", LevelVeryHigh, "Very-High")
	}
	out := heapCell[string](b)
	b.ReportAllocs()
	for b.Loop() {
		*out = LevelVeryHigh.String()
	}
}

func ExampleEvent_SeverityLevel() {
	var e Event
	if err := e.Parse([]byte("CEF:0|Vendor|Product|1.0|100|Name|very-high|"), MaxExtensions); err != nil {
		fmt.Println(err)
		return
	}
	level, num, ok := e.SeverityLevel()
	fmt.Println(level, num, ok)
	// Output: Very-High 10 true
}
