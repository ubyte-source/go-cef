package cef

import (
	"bytes"
	"slices"
)

// UnescapeHeader decodes \\ and \| in raw and keeps any other backslash: raw without a
// backslash comes back itself, capacity capped at its length, other raw decoded over
// dst[:0], dst may be raw[:0]; one allocation when dst has less room than raw.
func UnescapeHeader(raw, dst []byte) []byte {
	i := bytes.IndexByte(raw, '\\')
	if i < 0 {
		return slices.Clip(raw)
	}
	return unescape(raw, dst, i, classHeaderEscape)
}

// UnescapeExtValue decodes \\, \=, \n and \r in raw and keeps any other backslash: raw
// without a backslash comes back itself, capacity capped, other raw decoded over
// dst[:0], dst may be raw[:0]; one allocation when dst has less room than raw.
func UnescapeExtValue(raw, dst []byte) []byte {
	i := bytes.IndexByte(raw, '\\')
	if i < 0 {
		return slices.Clip(raw)
	}
	return unescape(raw, dst, i, classValueEscape)
}

// unescape decodes raw over dst[:0], grown to the length of raw, from its first
// backslash at i, the escapes of class resolved and a run of them walked in place.
func unescape(raw, dst []byte, i int, class byte) []byte {
	dst = append(slices.Grow(dst[:0], len(raw)), raw[:i]...)
	for rest := raw[i:]; len(rest) > 0; {
		if rest[0] != '\\' {
			j := bytes.IndexByte(rest, '\\')
			if j < 0 {
				return append(dst, rest...)
			}
			dst, rest = append(dst, rest[:j]...), rest[j:]
		}
		if len(rest) > 1 && byteClasses[rest[1]]&class != 0 {
			dst, rest = append(dst, unescaped(rest[1])), rest[2:]
			continue
		}
		dst, rest = append(dst, '\\'), rest[1:]
	}
	return dst
}

// unescaped returns the byte that a backslash and c stand for.
func unescaped(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	}
	return c
}
