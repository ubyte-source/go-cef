package cef

import "bytes"

// SeverityNum returns the numeric severity (0–10) for the parsed event.
// Named severities: Low=3, Medium=6, High=8, Very-High=10.
// Returns ([SeverityUnknown], true) for "Unknown".
// Returns (0, false) if the severity is invalid.
func (e *Event) SeverityNum() (int, bool) {
	b := e.severityBytes()
	if b == nil {
		return 0, false
	}
	if num, ok := parseDigitSeverity(b); ok {
		return num, true
	}
	name, num := matchNamedSeverity(b)
	if name == "" {
		return 0, false
	}
	return num, true
}

// SeverityLevel returns the normalized level string:
// "Low", "Medium", "High", "Very-High", or "Unknown".
// Returns ("", false) if unparseable.
func (e *Event) SeverityLevel() (string, bool) {
	b := e.severityBytes()
	if b == nil {
		return "", false
	}
	if num, ok := parseDigitSeverity(b); ok {
		return numToSeverityLevel(num), true
	}
	name, _ := matchNamedSeverity(b)
	if name == "" {
		return "", false
	}
	return name, true
}

func (e *Event) severityBytes() []byte {
	if e.raw == nil || e.Severity.IsEmpty() {
		return nil
	}
	return e.raw[e.Severity.Start:e.Severity.End]
}

func parseDigitSeverity(b []byte) (int, bool) {
	n := len(b)
	if n == 1 && b[0] >= '0' && b[0] <= '9' {
		return int(b[0] - '0'), true
	}
	if n == 2 && b[0] == '1' && b[1] == '0' {
		return 10, true
	}
	return -1, false
}

func numToSeverityLevel(num int) string {
	switch {
	case num < 0:
		return ""
	case num <= 3:
		return "Low"
	case num <= 6:
		return "Medium"
	case num <= 8:
		return "High"
	default:
		return "Very-High"
	}
}

func matchNamedSeverity(b []byte) (name string, num int) {
	if bytes.EqualFold(b, []byte("low")) {
		return "Low", 3
	}
	if bytes.EqualFold(b, []byte("medium")) {
		return "Medium", 6
	}
	if bytes.EqualFold(b, []byte("high")) {
		return "High", 8
	}
	if bytes.EqualFold(b, []byte("very-high")) {
		return "Very-High", 10
	}
	if bytes.EqualFold(b, []byte("unknown")) {
		return "Unknown", SeverityUnknown
	}
	return "", -1
}
