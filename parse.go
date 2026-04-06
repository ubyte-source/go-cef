package cef

import (
	"bytes"
	"math"
)

// safeU32 converts a non-negative int to uint32 with overflow protection.
func safeU32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		return 0
	}
	return uint32(n)
}

// fail returns the error result. In best-effort mode, the partial Event
// is returned alongside the error.
func (m *Parser) fail(pe *ParseError) (*Event, error) {
	if m.bestEffort {
		return &m.msg, pe
	}
	return nil, pe
}

// Parse parses the input as a CEF message.
//
// The returned *Event is valid until the next Parse call on the same Parser.
// The returned error, if non-nil, is a *[ParseError] whose value is also
// valid only until the next Parse call on the same Parser.
func (m *Parser) Parse(input []byte) (*Event, error) {
	m.resetMsg(input)

	if len(input) == 0 {
		return m.fail(m.makeError(0, ErrEmpty))
	}
	inputLen := len(input)
	if inputLen > math.MaxUint32 {
		return m.fail(m.makeError(0, ErrInputTooLarge))
	}
	n := safeU32(inputLen)

	p, err := m.parseVersion(input, n)
	if err != nil {
		return m.fail(err)
	}

	p, err = m.parseHeaderFields(input, p, n)
	if err != nil {
		return m.fail(err)
	}

	m.msg.headerComplete = true

	if p < n && input[p] == '|' {
		if extErr := m.parseExtensions(p + 1); extErr != nil {
			return m.fail(extErr)
		}
	}

	return &m.msg, nil
}

// ParseString is like [Parser.Parse] but accepts a string, avoiding the
// string→[]byte copy when the caller already has a string. The parser
// never modifies the input buffer.
func (m *Parser) ParseString(input string) (*Event, error) {
	if input == "" {
		return m.Parse(nil)
	}
	return m.Parse([]byte(input))
}

// resetMsg prepares the Event for a new parse.
func (m *Parser) resetMsg(input []byte) {
	m.msg.raw = input
	m.msg.Version = InvalidVersion
	m.msg.Vendor = Span{}
	m.msg.Product = Span{}
	m.msg.DevVersion = Span{}
	m.msg.ClassID = Span{}
	m.msg.Name = Span{}
	m.msg.Severity = Span{}
	m.msg.ExtCount = 0
	m.msg.headerComplete = false
}

// skipSpaces advances p past any space characters.
func skipSpaces(input []byte, p, n uint32) uint32 {
	for p < n && input[p] == ' ' {
		p++
	}
	return p
}

// scanDigits advances p past ASCII digits '0'–'9'.
func scanDigits(input []byte, p, n uint32) uint32 {
	for p < n && input[p] >= '0' && input[p] <= '9' {
		p++
	}
	return p
}

// parseVersion validates the "CEF:" prefix, skips optional whitespace,
// and parses the version number. Returns the position after "version|".
func (m *Parser) parseVersion(input []byte, n uint32) (uint32, *ParseError) {
	if n < 4 || string(input[:4]) != "CEF:" {
		return 0, m.makeError(0, ErrPrefix)
	}
	p := skipSpaces(input, 4, n)

	// Version: one or more ASCII digits.
	if p >= n || input[p] < '0' || input[p] > '9' {
		return p, m.makeError(p, ErrVersion)
	}
	vStart := p
	p = scanDigits(input, p, n)
	m.msg.Version = parseVersionBytes(input[vStart:p])
	if m.msg.Version < 0 {
		return vStart, m.makeError(vStart, ErrVersion)
	}

	if p >= n || input[p] != '|' {
		return p, m.makeError(p, ErrIncompleteHeader)
	}
	return p + 1, nil
}

// hasPipe checks whether input[p] is a pipe delimiter.
func hasPipe(input []byte, p, n uint32) bool {
	return p < n && input[p] == '|'
}

// parseHeaderFields parses the 6 pipe-delimited header fields
// (Vendor, Product, DevVersion, ClassID, Name, Severity).
// Unrolled for zero-indirection and better branch prediction.
func (m *Parser) parseHeaderFields(input []byte, p, n uint32) (uint32, *ParseError) {
	var start uint32

	start = p
	p = scanField(input, p, n, start)
	m.msg.Vendor = Span{start, p}
	if !hasPipe(input, p, n) {
		return p, m.makeError(p, ErrIncompleteHeader)
	}
	p++

	start = p
	p = scanField(input, p, n, start)
	m.msg.Product = Span{start, p}
	if !hasPipe(input, p, n) {
		return p, m.makeError(p, ErrIncompleteHeader)
	}
	p++

	start = p
	p = scanField(input, p, n, start)
	m.msg.DevVersion = Span{start, p}
	if !hasPipe(input, p, n) {
		return p, m.makeError(p, ErrIncompleteHeader)
	}
	p++

	start = p
	p = scanField(input, p, n, start)
	m.msg.ClassID = Span{start, p}
	if !hasPipe(input, p, n) {
		return p, m.makeError(p, ErrIncompleteHeader)
	}
	p++

	start = p
	p = scanField(input, p, n, start)
	m.msg.Name = Span{start, p}
	if !hasPipe(input, p, n) {
		return p, m.makeError(p, ErrIncompleteHeader)
	}
	p++

	start = p
	p = scanField(input, p, n, start)
	m.msg.Severity = Span{start, p}

	return p, nil
}

// scanField scans forward in input[p:n] for the next unescaped '|', returning
// its position. If no '|' is found, returns n.
func scanField(input []byte, p, n, start uint32) uint32 {
	if p >= n {
		return n
	}
	_ = input[n-1] // BCE hint
	for {
		idx := bytes.IndexByte(input[p:n], '|')
		if idx < 0 {
			return n
		}
		p += safeU32(idx)
		// Inline backward backslash count — only runs when '|' is found.
		if p > start && input[p-1] == '\\' {
			bs := uint32(1)
			for j := p - 1; j > start && input[j-1] == '\\'; j-- {
				bs++
			}
			if bs%2 == 1 {
				p++
				continue
			}
		}
		return p
	}
}

// parseVersionBytes converts ASCII digits to Version. Accepts 1–4 digits.
// Returns [InvalidVersion] for empty, >4 digits, or leading zeros.
//
// Precondition: all bytes in b must be ASCII digits '0'–'9'.
func parseVersionBytes(b []byte) Version {
	n := len(b)
	if n == 0 || n > 4 {
		return InvalidVersion
	}
	if n == 1 {
		return Version(b[0] - '0')
	}
	if b[0] == '0' {
		return InvalidVersion
	}
	var v Version
	for _, c := range b {
		v = v*10 + Version(c-'0')
	}
	return v
}
