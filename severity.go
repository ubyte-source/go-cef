package cef

// SeverityNum returns the numeric severity (0-10) for the parsed event.
// Named severities: Low=3, Medium=6, High=8, Very-High=10, Unknown=-1.
// Returns (0, false) if the severity field is invalid.
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
	switch len(b) {
	case 1:
		if b[0] >= '0' && b[0] <= '9' {
			return int(b[0] - '0'), true
		}
	case 2:
		if b[0] == '1' && b[1] == '0' {
			return 10, true
		}
	}
	return 0, false
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
	}
	return "Very-High"
}

// matchNamedSeverity dispatches by length and delegates the byte comparison.
func matchNamedSeverity(b []byte) (name string, num int) {
	switch len(b) {
	case 3:
		return matchLow(b)
	case 4:
		return matchHigh(b)
	case 6:
		return matchMedium(b)
	case 7:
		return matchUnknown(b)
	case 9:
		return matchVeryHigh(b)
	}
	return "", 0
}

// OR by 0x20 folds ASCII uppercase to lowercase; '-' and digits are preserved.
func matchLow(b []byte) (name string, num int) {
	if b[0]|0x20 == 'l' && b[1]|0x20 == 'o' && b[2]|0x20 == 'w' {
		return "Low", 3
	}
	return "", 0
}

func matchHigh(b []byte) (name string, num int) {
	if b[0]|0x20 == 'h' && b[1]|0x20 == 'i' && b[2]|0x20 == 'g' && b[3]|0x20 == 'h' {
		return "High", 8
	}
	return "", 0
}

func matchMedium(b []byte) (name string, num int) {
	if b[0]|0x20 == 'm' && b[1]|0x20 == 'e' && b[2]|0x20 == 'd' &&
		b[3]|0x20 == 'i' && b[4]|0x20 == 'u' && b[5]|0x20 == 'm' {
		return "Medium", 6
	}
	return "", 0
}

func matchUnknown(b []byte) (name string, num int) {
	if b[0]|0x20 == 'u' && b[1]|0x20 == 'n' && b[2]|0x20 == 'k' && b[3]|0x20 == 'n' &&
		b[4]|0x20 == 'o' && b[5]|0x20 == 'w' && b[6]|0x20 == 'n' {
		return "Unknown", SeverityUnknown
	}
	return "", 0
}

func matchVeryHigh(b []byte) (name string, num int) {
	if b[4] == '-' &&
		b[0]|0x20 == 'v' && b[1]|0x20 == 'e' && b[2]|0x20 == 'r' && b[3]|0x20 == 'y' &&
		b[5]|0x20 == 'h' && b[6]|0x20 == 'i' && b[7]|0x20 == 'g' && b[8]|0x20 == 'h' {
		return "Very-High", 10
	}
	return "", 0
}
