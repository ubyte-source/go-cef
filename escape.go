package cef

import "math/bits"

// Text is the bytes of a header field, an extension value or a key in a string or a
// byte slice, named types included.
type Text interface{ ~string | ~[]byte }

// AppendEscapedHeader appends field to dst with '\' and '|' escaped and each CR or LF
// written as a space, since a header field holds one line: UnescapeHeader gives back
// single-line text as it was. No allocation when dst has room.
func AppendEscapedHeader[T Text](dst []byte, field T) []byte {
	return appendEscaped(dst, field, classHeaderSpecial)
}

// AppendEscapedExtValue appends value to dst with '\' and '=' escaped and CR and LF
// written as \r and \n, the inverse of UnescapeExtValue; Parse drops trailing spaces of
// the last pair's value. No allocation when dst has room.
func AppendEscapedExtValue[T Text](dst []byte, value T) []byte {
	return appendEscaped(dst, value, classValueSpecial)
}

// ValidKey reports whether key is one or more of A-Z, a-z, 0-9, '.', '_', '-', '[' and
// ']', the bytes of the keys Parse reads.
func ValidKey[T Text](key T) bool {
	for i := range len(key) {
		if byteClasses[key[i]]&classKey == 0 {
			return false
		}
	}
	return len(key) > 0
}

// appendEscaped appends s to dst with each byte of class, classHeaderSpecial with '|'
// or else classValueSpecial with '=', written as its escape; it reads only the bytes
// escapeLanes marks in each word, and each of the last bytes that fill no word.
func appendEscaped[T Text](dst []byte, s T, class byte) []byte {
	sep := byte('=')
	if class == classHeaderSpecial {
		sep = '|'
	}
	start, i := 0, 0
	for ; i+scanBytes <= len(s); i += scanBytes {
		for m := escapeLanes(textWord(s[i:]), sep); m != 0; m &= m - 1 {
			dst, start = escapeAt(dst, s, start, i+bits.TrailingZeros64(m)/laneBits, class)
		}
	}
	for ; i < len(s); i++ {
		dst, start = escapeAt(dst, s, start, i, class)
	}
	return append(dst, s[start:]...)
}

// escapeAt appends s[start:j] and the escape of s[j] to dst when s[j] is of class, and
// returns dst and from, the start of the bytes of s left to append.
func escapeAt[T Text](dst []byte, s T, start, j int, class byte) (out []byte, from int) {
	if c := s[j]; byteClasses[c]&class != 0 {
		return appendEscape(append(dst, s[start:j]...), c, class), j + 1
	}
	return dst, start
}

// textWord returns the first scanBytes bytes of s, which holds that many, as a
// little-endian word.
func textWord[T Text](s T) uint64 {
	b := s[:scanBytes]
	return uint64(b[0]) | uint64(b[1])<<lane1 | uint64(b[2])<<lane2 | uint64(b[3])<<lane3 |
		uint64(b[4])<<lane4 | uint64(b[5])<<lane5 | uint64(b[6])<<lane6 | uint64(b[7])<<lane7
}

// escapeLanes returns laneHigh's bit in each byte of w that is a backslash, sep or a
// byte below a space, and 0 elsewhere.
func escapeLanes(w uint64, sep byte) uint64 {
	below := ^((w&laneLow7 + (laneHigh - ' '*laneOnes)) | w) & laneHigh
	return zeroLanes(w^'\\'*laneOnes) | zeroLanes(w^uint64(sep)*laneOnes) | below
}

// appendEscape appends the escape of c, a byte of class: a space for a CR or LF in a
// header field, \r or \n in a value, and a backslash before any other byte.
func appendEscape(dst []byte, c, class byte) []byte {
	switch {
	case c != '\r' && c != '\n':
		return append(dst, '\\', c)
	case class == classHeaderSpecial:
		return append(dst, ' ')
	case c == '\r':
		return append(dst, '\\', 'r')
	}
	return append(dst, '\\', 'n')
}

// Byte classes of byteClasses, one bit each.
const (
	classKey           = 1 << iota // a byte a key holds
	classHeaderEscape              // a byte a backslash escapes in a header field
	classValueEscape               // a byte a backslash escapes in an extension value
	classHeaderSpecial             // a byte AppendEscapedHeader rewrites
	classValueSpecial              // a byte AppendEscapedExtValue rewrites
	classTrailing                  // a byte Parse drops from the end of an extension
)

// byteClasses holds at index c the classes of the byte c.
const byteClasses = "" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x00\x00\x38\x00\x00" + // 0x00
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0x10
	"\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00" + // 0x20
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x14\x00\x00" + // 0x30
	"\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" + // 0x40
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x1e\x01\x00\x01" + // 0x50
	"\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x05\x01" + // 0x60
	"\x01\x01\x05\x01\x01\x01\x01\x01\x01\x01\x01\x00\x0a\x00\x00\x00" + // 0x70
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0x80
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0x90
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0xa0
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0xb0
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0xc0
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0xd0
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // 0xe0
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" // 0xf0
