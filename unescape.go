package cef

import "bytes"

type escapeTable [256]byte

var headerEscapes = func() escapeTable {
	var t escapeTable
	t['|'] = '|'
	t['\\'] = '\\'
	return t
}()

var extEscapes = func() escapeTable {
	var t escapeTable
	t['='] = '='
	t['\\'] = '\\'
	t['n'] = '\n'
	t['r'] = '\r'
	return t
}()

// UnescapeHeader unescapes a CEF header field (\| -> |, \\ -> \).
// Returns raw unchanged if no '\' is present; else writes into dst.
func UnescapeHeader(raw, dst []byte) []byte {
	if bytes.IndexByte(raw, '\\') < 0 {
		return raw
	}
	return unescape(raw, dst, &headerEscapes)
}

// UnescapeExtValue unescapes a CEF extension value
// (\= -> =, \\ -> \, \n -> LF, \r -> CR).
func UnescapeExtValue(raw, dst []byte) []byte {
	if bytes.IndexByte(raw, '\\') < 0 {
		return raw
	}
	return unescape(raw, dst, &extEscapes)
}

func unescape(raw, dst []byte, table *escapeTable) []byte {
	if cap(dst) < len(raw) {
		dst = make([]byte, 0, len(raw))
	} else {
		dst = dst[:0]
	}

	i := 0
	for i < len(raw) {
		j := bytes.IndexByte(raw[i:], '\\')
		if j < 0 {
			dst = append(dst, raw[i:]...)
			break
		}
		dst = append(dst, raw[i:i+j]...)
		i += j

		if i+1 >= len(raw) {
			dst = append(dst, raw[i])
			break
		}
		if repl := table[raw[i+1]]; repl != 0 {
			dst = append(dst, repl)
			i += 2
		} else {
			dst = append(dst, raw[i])
			i++
		}
	}
	return dst
}
