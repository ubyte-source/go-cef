package cef

import "testing"

func TestSeverityNum(t *testing.T) {
	tests := []struct {
		sev    string
		want   int
		wantOK bool
	}{
		{"0", 0, true}, {"1", 1, true}, {"2", 2, true}, {"3", 3, true},
		{"4", 4, true}, {"5", 5, true}, {"6", 6, true}, {"7", 7, true},
		{"8", 8, true}, {"9", 9, true}, {"10", 10, true},
		{"Low", 3, true}, {"low", 3, true}, {"LOW", 3, true},
		{"Medium", 6, true}, {"medium", 6, true}, {"MEDIUM", 6, true},
		{"High", 8, true}, {"high", 8, true}, {"HIGH", 8, true},
		{"Very-High", 10, true}, {"very-high", 10, true}, {"VERY-HIGH", 10, true},
		{"Unknown", -1, true}, {"unknown", -1, true}, {"UNKNOWN", -1, true},
		{"", 0, false}, {"invalid", 0, false}, {"11", 0, false}, {"abc", 0, false},
		// Boundary cases (G5)
		{"00", 0, false}, {"99", 0, false}, {"-1", 0, false}, {"100", 0, false},
		{"01", 0, false}, {"1 ", 0, false}, {" 1", 0, false},
	}
	m := NewParser()
	for _, tt := range tests {
		t.Run(tt.sev, func(t *testing.T) {
			input := []byte(`CEF:0|V|P|1|100|N|` + tt.sev + `|`)
			e, err := m.Parse(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, ok := e.SeverityNum()
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("SeverityNum(%q): got (%d, %v), want (%d, %v)", tt.sev, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		sev    string
		want   string
		wantOK bool
	}{
		{"0", "Low", true}, {"1", "Low", true}, {"2", "Low", true}, {"3", "Low", true},
		{"4", "Medium", true}, {"5", "Medium", true}, {"6", "Medium", true},
		{"7", "High", true}, {"8", "High", true},
		{"9", "Very-High", true}, {"10", "Very-High", true},
		{"Low", "Low", true}, {"Medium", "Medium", true}, {"High", "High", true},
		{"Very-High", "Very-High", true}, {"Unknown", "Unknown", true},
		{"low", "Low", true}, {"medium", "Medium", true}, {"high", "High", true},
		{"", "", false}, {"invalid", "", false}, {"abc", "", false},
	}
	m := NewParser()
	for _, tt := range tests {
		t.Run(tt.sev, func(t *testing.T) {
			input := []byte(`CEF:0|V|P|1|100|N|` + tt.sev + `|`)
			e, err := m.Parse(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, ok := e.SeverityLevel()
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("SeverityLevel(%q): got (%q, %v), want (%q, %v)", tt.sev, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestSeverityNum_NilRaw(t *testing.T) {
	e := &Event{}
	got, ok := e.SeverityNum()
	if got != 0 || ok {
		t.Errorf("expected (0, false), got (%d, %v)", got, ok)
	}
}

func TestSeverityLevel_NilRaw(t *testing.T) {
	e := &Event{}
	got, ok := e.SeverityLevel()
	if got != "" || ok {
		t.Errorf("expected (\"\", false), got (%q, %v)", got, ok)
	}
}

func TestNumToSeverityLevelNegative(t *testing.T) {
	// Defensive branch: numToSeverityLevel with negative input.
	if got := numToSeverityLevel(-1); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
