package cef

import (
	"encoding/binary"
	"strconv"
)

// Level is a severity level of the Severity field, which SeverityLevel classifies.
type Level uint8

// The levels of the Severity field: 0 is Unknown, 1-3 Low, 4-6 Medium, 7-8 High, 9-10
// Very-High.
const (
	LevelUnknown Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelVeryHigh
)

// String returns the name of l as the Severity field writes it, "Unknown", "Low",
// "Medium", "High" or "Very-High", with no allocation, and "Level(N)" for another l.
func (l Level) String() string {
	if l > LevelVeryHigh {
		return l.number()
	}
	return levelNames[levelStarts[l]:levelStarts[l+1]]
}

// The names of the levels, the name of l starting at levelStarts[l] and ending where
// the next one starts.
const (
	levelNames  = "UnknownLowMediumHighVery-High"
	levelStarts = "\x00\x07\x0a\x10\x14\x1d"
)

// number returns l as "Level(N)", N in decimal.
func (l Level) number() string {
	var buf [len("Level(255)")]byte
	b := strconv.AppendUint(append(buf[:0], "Level("...), uint64(l), decimal)
	return string(append(b, ')'))
}

// SeverityLevel classifies the Severity field once: an integer 0 to 10 gives its level
// and itself, a name in any letter case Unknown 0, Low 3, Medium 6, High 8 or Very-High
// 10, and anything else LevelUnknown, 0 and false. No allocation.
func (e *Event) SeverityLevel() (level Level, num int, ok bool) {
	return classify(e.raw, e.header[fieldSeverity])
}

// numberLevels holds at index n the Level of the integer severity n.
const numberLevels = "\x00\x01\x01\x01\x02\x02\x02\x03\x03\x04\x04"

// levelNumbers holds at index l the number that the name of the Level l stands for.
const levelNumbers = "\x00\x03\x06\x08\x0a"

// classify returns the level, the number and the validity of the severity field s of
// raw: one digit, "10", or a name.
func classify(raw []byte, s Span) (Level, int, bool) {
	b := view(raw, s)
	var level Level
	ok := false
	switch len(b) {
	case len("7"):
		return digitLevel(b[0])
	case len("10"):
		level, ok = LevelVeryHigh, string(b) == "10"
	case len("Low"):
		level, ok = LevelLow, isLow(b)
	case len("High"):
		level, ok = LevelHigh, binary.LittleEndian.Uint32(b)|letterFolds == highWord
	case len("Medium"):
		level, ok = LevelMedium, foldMatch(b, mediWord, diumWord)
	case len("Unknown"):
		level, ok = LevelUnknown, foldMatch(b, unknWord, nownWord)
	case len("Very-High"):
		level, ok = LevelVeryHigh, foldMatch(b, veryWord, highWord) && b[len("Very")] == '-'
	}
	if !ok {
		return LevelUnknown, 0, false
	}
	return level, int(levelNumbers[level]), true
}

// digitLevel returns the level and the number of the one-byte severity field c.
func digitLevel(c byte) (Level, int, bool) {
	if d := c - '0'; d < decimal {
		return Level(numberLevels[d]), int(d), true
	}
	return LevelUnknown, 0, false
}

// isLow reports whether b, of three bytes, is "low" in any letter case.
func isLow(b []byte) bool {
	return b[0]|letterFold == 'l' && b[1]|letterFold == 'o' && b[2]|letterFold == 'w'
}

// Letter folds: setting the 0x20 bit of an ASCII letter gives its lower case, in one
// byte or in each byte of a word.
const (
	letterFold  = 0x20
	letterFolds = 0x20202020
)

// Words of the level names in lower case, as little-endian words of four bytes.
const (
	highWord = 'h' | 'i'<<lane1 | 'g'<<lane2 | 'h'<<lane3
	mediWord = 'm' | 'e'<<lane1 | 'd'<<lane2 | 'i'<<lane3
	diumWord = 'd' | 'i'<<lane1 | 'u'<<lane2 | 'm'<<lane3
	unknWord = 'u' | 'n'<<lane1 | 'k'<<lane2 | 'n'<<lane3
	nownWord = 'n' | 'o'<<lane1 | 'w'<<lane2 | 'n'<<lane3
	veryWord = 'v' | 'e'<<lane1 | 'r'<<lane2 | 'y'<<lane3
)

// foldMatch reports whether the first and the last word of b, of wordLen bytes or more,
// are first and last once its letters are folded to lower case.
func foldMatch(b []byte, first, last uint32) bool {
	return binary.LittleEndian.Uint32(b)|letterFolds == first &&
		binary.LittleEndian.Uint32(b[len(b)-wordLen:])|letterFolds == last
}
