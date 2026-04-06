package cef

import "bytes"

const maxKeyLen = 63 // generous upper bound for CEF key length

// maxEqualsScanned is the DoS budget: at most this many '=' signs are
// examined per extension value. 256 limits the worst-case scan to roughly
// 256 × 63 ≈ 16 KiB per value — sufficient for all known vendor formats
// while bounding adversarial input cost.
const maxEqualsScanned = 256

// parseExtensions parses extension key=value pairs starting at pos.
func (m *Parser) parseExtensions(pos uint32) *ParseError {
	data := m.msg.raw
	end := safeU32(len(data))
	if pos >= end {
		return nil
	}
	_ = data[end-1] // BCE hint: eliminate bounds checks in the loop

	n := 0
	maxExt := m.maxExtensions

	pos = skipSpaces(data, pos, end)

	for pos < end && n < maxExt {
		idx := bytes.IndexByte(data[pos:end], '=')
		if idx < 0 {
			break
		}
		eq := pos + safeU32(idx)

		keyStart := pos
		keyEnd := eq
		// For the first key, validate explicitly. For subsequent keys,
		// findValueEnd already validated the candidate that became this key.
		if n == 0 && !validKey(data[keyStart:keyEnd]) {
			if m.bestEffort {
				break
			}
			return m.makeError(pos, ErrExtKey)
		}

		valStart := eq + 1
		valEnd := findValueEnd(data, valStart, end)

		m.msg.exts[n] = ExtPair{
			Key:   Span{keyStart, keyEnd},
			Value: Span{valStart, valEnd},
		}
		n++

		pos = skipSpaces(data, valEnd, end)
	}

	m.msg.ExtCount = n

	if n >= maxExt && pos < end {
		return m.checkExtOverflow(pos, end)
	}

	return nil
}

// checkExtOverflow checks whether more extensions remain after the limit.
func (m *Parser) checkExtOverflow(pos, end uint32) *ParseError {
	data := m.msg.raw
	idx := bytes.IndexByte(data[pos:end], '=')
	if idx >= 0 && validKey(data[pos:pos+safeU32(idx)]) {
		if !m.bestEffort {
			return m.makeError(pos, ErrExtOverflow)
		}
	}
	return nil
}

// isEscapedEquals checks if the '=' at position eq is preceded by an
// odd number of backslashes (i.e., it is escaped).
func isEscapedEquals(data []byte, eq, minPos uint32) bool {
	if eq <= minPos || data[eq-1] != '\\' {
		return false
	}
	bs := uint32(1)
	for j := eq - 1; j > minPos && data[j-1] == '\\'; j-- {
		bs++
	}
	return bs%2 == 1
}

// findKeyBeforeEquals looks for a valid key between a space and the '=' at eq.
// Returns the space position and true if a valid key is found.
func findKeyBeforeEquals(data []byte, i, eq uint32) (uint32, bool) {
	limit := i
	if eq > maxKeyLen && eq-maxKeyLen > limit {
		limit = eq - maxKeyLen
	}
	spIdx := bytes.LastIndexByte(data[limit:eq], ' ')
	if spIdx < 0 {
		return 0, false
	}
	spacePos := limit + safeU32(spIdx)
	if spacePos < i {
		return 0, false
	}
	if validKey(data[spacePos+1 : eq]) {
		return spacePos, true
	}
	return 0, false
}

// findValueEnd scans forward for the pattern "SPACE key_chars '='" to find
// where the current value ends and the next key begins.
//
// Worst case: O(maxEqualsScanned × maxKeyLen) ≈ O(16 128) bytes scanned
// per value, bounded by the DoS budget.
func findValueEnd(data []byte, start, end uint32) uint32 {
	if start >= end {
		return end
	}
	_ = data[end-1] // BCE hint

	i := start
	budget := maxEqualsScanned
	for i < end {
		idx := bytes.IndexByte(data[i:end], '=')
		if idx < 0 {
			return trimTrailingSpaces(data, start, end)
		}
		eq := i + safeU32(idx)

		budget--
		if budget <= 0 {
			return trimTrailingSpaces(data, start, end)
		}

		if isEscapedEquals(data, eq, start) {
			i = eq + 1
			continue
		}

		if eq <= i+1 {
			i = eq + 1
			continue
		}

		if sp, ok := findKeyBeforeEquals(data, i, eq); ok {
			return sp
		}

		i = eq + 1
	}
	return trimTrailingSpaces(data, start, end)
}

// validKey checks if b is a valid CEF extension key.
func validKey(b []byte) bool {
	n := len(b)
	if n == 0 || n > maxKeyLen {
		return false
	}
	_ = b[len(b)-1] // BCE hint
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
