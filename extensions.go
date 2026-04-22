package cef

import (
	"bytes"
	"math"
)

const (
	maxKeyLen        = 63
	maxEqualsScanned = 256
)

// isKeyByte is a 256-entry lookup for valid key chars [a-zA-Z0-9._\-\[\]].
var isKeyByte = func() [256]bool {
	var t [256]bool
	for c := byte('a'); c <= 'z'; c++ {
		t[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		t[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		t[c] = true
	}
	t['.'] = true
	t['_'] = true
	t['-'] = true
	t['['] = true
	t[']'] = true
	return t
}()

func (p *Parser) parseExtensions(pos uint32) *ParseError {
	data := p.msg.raw
	end := uint32(len(data) & math.MaxUint32)
	if pos >= end {
		return nil
	}

	n := 0
	maxExt := p.maxExtensions

	pos = skipSpaces(data, pos, end)

	for pos < end && n < maxExt {
		idx := bytes.IndexByte(data[pos:end], '=')
		if idx < 0 {
			break
		}
		eq := pos + uint32(idx&math.MaxUint32)

		keyStart := pos
		keyEnd := eq
		if n == 0 && !validKey(data[keyStart:keyEnd]) {
			if p.bestEffort {
				break
			}
			return p.makeError(pos, ErrExtKey)
		}

		valStart := eq + 1
		valEnd := findValueEnd(data, valStart, end)

		p.msg.extKeys[n] = Span{keyStart, keyEnd}
		p.msg.extVals[n] = Span{valStart, valEnd}
		p.msg.extPacks[n] = keyPackBytes(data[keyStart:keyEnd])
		n++

		pos = skipSpaces(data, valEnd, end)
	}

	p.msg.ExtCount = n

	if n >= maxExt && pos < end {
		return p.checkExtOverflow(pos, end)
	}
	return nil
}

func (p *Parser) checkExtOverflow(pos, end uint32) *ParseError {
	data := p.msg.raw
	idx := bytes.IndexByte(data[pos:end], '=')
	if idx >= 0 && validKey(data[pos:pos+uint32(idx&math.MaxUint32)]) && !p.bestEffort {
		return p.makeError(pos, ErrExtOverflow)
	}
	return nil
}

// findKeyBeforeEquals scans [i, eq) backward for a " key=" pattern.
func findKeyBeforeEquals(data []byte, i, eq uint32) (uint32, bool) {
	limit := i
	if eq > maxKeyLen && eq-maxKeyLen > i {
		limit = eq - maxKeyLen
	}
	for j := eq; j > limit; j-- {
		if data[j-1] != ' ' {
			continue
		}
		spacePos := j - 1
		if validKey(data[spacePos+1 : eq]) {
			return spacePos, true
		}
		return 0, false
	}
	return 0, false
}

// findValueEnd scans forward for the next " key=" boundary. Bounded by
// maxEqualsScanned for DoS resistance.
func findValueEnd(data []byte, start, end uint32) uint32 {
	if start >= end {
		return end
	}
	i := start
	budget := maxEqualsScanned
	for i < end {
		idx := bytes.IndexByte(data[i:end], '=')
		if idx < 0 {
			return trimTrailingSpaces(data, start, end)
		}
		eq := i + uint32(idx&math.MaxUint32)

		budget--
		if budget <= 0 {
			return trimTrailingSpaces(data, start, end)
		}

		if isEscapedDelim(data, eq, start) {
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

func validKey(b []byte) bool {
	n := len(b)
	if n == 0 || n > maxKeyLen {
		return false
	}
	for _, c := range b {
		if !isKeyByte[c] {
			return false
		}
	}
	return true
}

func trimTrailingSpaces(data []byte, start, end uint32) uint32 {
	for end > start && data[end-1] == ' ' {
		end--
	}
	return end
}
