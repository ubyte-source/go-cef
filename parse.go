package cef

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/bits"
)

// MaxExtensions is the pair limit of UnmarshalText and of the text methods, and the
// limit to pass to Parse for a caller that declares none of its own.
const MaxExtensions = 256

// Shape of the event prefix: the bytes that open an event, and the most digits of a
// version.
const (
	cefPrefix     = "CEF:"
	versionDigits = 4
)

// Parse reads input, which starts with "CEF:", into e: the version, six header fields
// to the seventh unescaped '|' and at most maxExtensions pairs. It allocates only to
// grow e's pairs and, on a fault, the *ParseError; e keeps what precedes a fault.
func (e *Event) Parse(input []byte, maxExtensions int) error {
	if exceedsSpans(len(input)) {
		e.Reset()
		return fault(0, ErrInputTooLarge)
	}
	e.restart(input)
	if len(input) == 0 {
		return fault(0, ErrEmpty)
	}
	p, err := e.parseVersion(input)
	if err != nil {
		return err
	}
	if p, err = e.parseHeader(input, p); err != nil {
		return err
	}
	e.headerComplete = true
	return e.parseExtensions(p, maxExtensions)
}

// exceedsSpans reports whether an input of n bytes holds positions a Span cannot.
func exceedsSpans(n int) bool { return int64(n) > math.MaxUint32 }

// offset returns the input position i as a Span offset.
//
//nolint:gosec // Parse refuses an input whose positions exceed math.MaxUint32
func offset(i int) uint32 { return uint32(i) }

// parseVersion reads the prefix and the version token, the bytes up to the first '|'
// after leading spaces, and returns the position after that '|'.
func (e *Event) parseVersion(input []byte) (int, error) {
	if len(input) < len(cefPrefix) || string(input[:len(cefPrefix)]) != cefPrefix {
		return 0, fault(0, ErrPrefix)
	}
	start := skipSpaces(input, len(cefPrefix))
	v, n, ok := versionToken(input[start:])
	if !ok {
		return start, fault(start, ErrVersion)
	}
	p := start + n
	e.version = v
	if p == len(input) {
		return p, fault(p, ErrIncompleteHeader)
	}
	return p + 1, nil
}

// versionToken reads the digits that b starts with, versionDigits+1 at most, and
// returns their value, their count, and whether they are a version that the end of b
// or a '|' follows.
func versionToken(b []byte) (v uint16, n int, ok bool) {
	for n < len(b) && n <= versionDigits && isDigit(b[n]) {
		v = v*decimal + uint16(b[n]-'0')
		n++
	}
	ok = n > 0 && n <= versionDigits && (n == 1 || b[0] != '0') && (n == len(b) || b[n] == '|')
	return v, n, ok
}

// isDigit reports whether c is an ASCII decimal digit.
func isDigit(c byte) bool { return c-'0' < decimal }

// skipSpaces returns the position of the first byte at or after p that is not a space.
func skipSpaces(b []byte, p int) int {
	for p < len(b) && b[p] == ' ' {
		p++
	}
	return p
}

// parseHeader reads the six header fields from p, each ended by a '|' that no
// backslash escapes, a word at a time, and returns the position after the seventh '|';
// a field whose '|' follows a backslash goes to parseFields.
func (e *Event) parseHeader(input []byte, p int) (int, error) {
	if len(input) < scanBytes {
		return e.parseFields(input, p, 0)
	}
	field, start := 0, p
	for ; p < len(input); p += scanBytes {
		for m := pipeLanes(wordAt(input, p)); m != 0; m &= m - 1 {
			q := p + bits.TrailingZeros64(m)/laneBits
			if input[q-1] == '\\' {
				return e.parseFields(input, start, field)
			}
			e.header[field] = Span{Start: offset(start), End: offset(q)}
			if field, start = field+1, q+1; field == headerFields {
				return start, nil
			}
		}
	}
	return e.parseFields(input, start, field)
}

// parseFields reads the header fields from index field on, the first at p, each with
// fieldEnd, and returns the position after the seventh '|'.
func (e *Event) parseFields(input []byte, p, field int) (int, error) {
	for i := field; i < headerFields; i++ {
		end := fieldEnd(input, p)
		e.header[i] = Span{Start: offset(p), End: offset(end)}
		if end == len(input) {
			return end, fault(end, ErrIncompleteHeader)
		}
		p = end + 1
	}
	return p, nil
}

// wordAt returns the scanBytes bytes of input from p as a little-endian word, zero past
// the end of input, which holds scanBytes bytes or more.
func wordAt(input []byte, p int) uint64 {
	if p+scanBytes <= len(input) {
		return binary.LittleEndian.Uint64(input[p:])
	}
	tail := len(input) - scanBytes
	return binary.LittleEndian.Uint64(input[tail:]) >> ((p - tail) * laneBits)
}

// pipeLanes returns laneHigh's bit in each byte of w that is a '|', and 0 elsewhere.
func pipeLanes(w uint64) uint64 { return zeroLanes(w ^ '|'*laneOnes) }

// fieldEnd returns the position of the first '|' at or after p that no backslash
// escapes, or len(input) when there is none; after an escaped '|' it walks the escape
// pairs that follow, so a run of them costs no search per pair.
func fieldEnd(input []byte, p int) int {
	start := p
	for {
		i := bytes.IndexByte(input[p:], '|')
		if i < 0 {
			return len(input)
		}
		q := p + i
		if !oddBackslashes(input[start:q]) {
			return q
		}
		p = q + 1
		for p+1 < len(input) && input[p] == '\\' {
			p += 2
		}
		if p < len(input) && input[p] == '|' {
			return p
		}
	}
}

// oddBackslashes reports whether b ends in an odd run of backslashes, the run that
// escapes the byte after b.
func oddBackslashes(b []byte) bool {
	i := len(b)
	for i > 0 && b[i-1] == '\\' {
		i--
	}
	return (len(b)-i)&1 == 1
}
