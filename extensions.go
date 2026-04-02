package cef

import "bytes"

const maxKeyLen = 63         // generous upper bound for CEF key length
const maxEqualsScanned = 256 // DoS budget: max '=' examined per value

// parseExtensions parses extension key=value pairs starting at pos.
func (m *Parser) parseExtensions(pos uint32) *ParseError {
	data := m.msg.raw
	end := toU32(len(data))
	n := 0
	maxExt := m.maxExtensions

	for pos < end && data[pos] == ' ' {
		pos++
	}

	for pos < end && n < maxExt {
		eq, ok := indexByteFrom(data, pos, '=')
		if !ok {
			break
		}

		keyStart := pos
		keyEnd := eq
		if !validKey(data[keyStart:keyEnd]) {
			if m.bestEffort {
				break
			}
			return newParseError(pos, ErrExtKey)
		}

		valStart := eq + 1
		valEnd := findValueEnd(data, valStart, end)

		m.msg.exts[n] = ExtPair{
			Key:   Span{keyStart, keyEnd},
			Value: Span{valStart, valEnd},
		}
		n++

		pos = valEnd
		for pos < end && data[pos] == ' ' {
			pos++
		}
	}

	m.msg.ExtCount = n

	if n >= maxExt && pos < end {
		eq, ok := indexByteFrom(data, pos, '=')
		if ok && validKey(data[pos:eq]) {
			if !m.bestEffort {
				return newParseError(pos, ErrExtOverflow)
			}
		}
	}

	return nil
}

// findValueEnd scans forward for the pattern "SPACE key_chars '='" to find
// where the current value ends and the next key begins.
func findValueEnd(data []byte, start, end uint32) uint32 {
	i := start
	budget := maxEqualsScanned
	for i < end {
		eq, ok := indexByteFrom(data, i, '=')
		if !ok {
			return trimTrailingSpaces(data, start, end)
		}

		budget--
		if budget <= 0 {
			return trimTrailingSpaces(data, start, end)
		}

		if isEscapedAt(data, eq, start) {
			i = eq + 1
			continue
		}

		if eq <= i+1 {
			i = eq + 1
			continue
		}

		limit := i
		if eq > maxKeyLen && eq-maxKeyLen > limit {
			limit = eq - maxKeyLen
		}

		if idx := bytes.LastIndexByte(data[limit:eq], ' '); idx >= 0 {
			spacePos := limit + toU32(idx)
			if spacePos >= i {
				candidate := data[spacePos+1 : eq]
				if validKey(candidate) {
					return spacePos
				}
			}
		}

		i = eq + 1
	}
	return trimTrailingSpaces(data, start, end)
}

// isEscapedAt reports whether the byte at pos is preceded by an odd number
// of backslashes.
func isEscapedAt(data []byte, pos, minPos uint32) bool {
	if pos <= minPos || data[pos-1] != '\\' {
		return false
	}
	n := uint32(0)
	j := pos
	for j > minPos && data[j-1] == '\\' {
		n++
		j--
	}
	return n%2 == 1
}

// validKey checks if b is a valid CEF extension key.
func validKey(b []byte) bool {
	n := len(b)
	if n == 0 || n > maxKeyLen {
		return false
	}
	for _, c := range b {
		if !isKeyChar(c) {
			return false
		}
	}
	return true
}

// isKeyBitset is a [4]uint64 lookup for valid key characters [a-zA-Z0-9._\-\[\]].
var isKeyBitset = func() [4]uint64 {
	var t [4]uint64
	set := func(c byte) { t[c/64] |= 1 << (c % 64) }
	for c := byte('a'); c <= 'z'; c++ {
		set(c)
	}
	for c := byte('A'); c <= 'Z'; c++ {
		set(c)
	}
	for c := byte('0'); c <= '9'; c++ {
		set(c)
	}
	for _, c := range []byte{'.', '_', '-', '[', ']'} {
		set(c)
	}
	return t
}()

// isKeyChar returns true if c is valid in a CEF extension key.
func isKeyChar(c byte) bool {
	return isKeyBitset[c/64]&(1<<(c%64)) != 0
}

func trimTrailingSpaces(data []byte, start, end uint32) uint32 {
	for end > start && data[end-1] == ' ' {
		end--
	}
	return end
}

// indexByteFrom finds the first c in data[start:] and returns the absolute index.
func indexByteFrom(data []byte, start uint32, c byte) (uint32, bool) {
	if int(start) >= len(data) {
		return 0, false
	}
	idx := bytes.IndexByte(data[start:], c)
	if idx < 0 {
		return 0, false
	}
	return start + toU32(idx), true
}
