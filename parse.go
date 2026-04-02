package cef

import (
	"bytes"
	"math"
)

// toU32 safely converts a non-negative int to uint32, clamping at MaxUint32.
func toU32(n int) uint32 {
	if n > math.MaxUint32 {
		return math.MaxUint32
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
// The returned error, if non-nil, is a *[ParseError]; each call returns an
// independent error value.
func (m *Parser) Parse(input []byte) (*Event, error) {
	m.resetMsg(input)

	if len(input) == 0 {
		return m.fail(newParseError(0, ErrEmpty))
	}
	if len(input) > math.MaxUint32 {
		return m.fail(newParseError(0, ErrInputTooLarge))
	}

	p, err := m.parseVersion(input)
	if err != nil {
		return m.fail(err)
	}

	p, err = m.parseHeaderFields(input, p)
	if err != nil {
		return m.fail(err)
	}

	m.msg.headerComplete = true

	n := toU32(len(input))
	if p < n && input[p] == '|' {
		if extErr := m.parseExtensions(p + 1); extErr != nil {
			return m.fail(extErr)
		}
	}

	return &m.msg, nil
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

// parseVersion validates the "CEF:" prefix, skips optional whitespace,
// and parses the version number. Returns the position after "version|".
func (m *Parser) parseVersion(input []byte) (uint32, *ParseError) {
	n := toU32(len(input))
	if n < 4 || string(input[:4]) != "CEF:" {
		return 0, newParseError(0, ErrPrefix)
	}
	p := uint32(4)

	// Skip optional whitespace (some vendors emit "CEF: 0").
	for int(p) < len(input) && input[p] == ' ' {
		p++
	}

	// Version: one or more ASCII digits.
	if int(p) >= len(input) || input[p] < '0' || input[p] > '9' {
		return p, newParseError(p, ErrVersion)
	}
	vStart := p
	for p < n && input[p] >= '0' && input[p] <= '9' {
		p++
	}
	m.msg.Version = parseVersionBytes(input[vStart:p])
	if m.msg.Version < 0 {
		return vStart, newParseError(vStart, ErrVersion)
	}

	if p >= n || input[p] != '|' {
		return p, newParseError(p, ErrIncompleteHeader)
	}
	p++
	return p, nil
}

// parseHeaderFields parses the 6 pipe-delimited header fields
// (Vendor, Product, DevVersion, ClassID, Name, Severity).
func (m *Parser) parseHeaderFields(input []byte, p uint32) (uint32, *ParseError) {
	n := toU32(len(input))
	spans := [6]*Span{
		&m.msg.Vendor, &m.msg.Product, &m.msg.DevVersion,
		&m.msg.ClassID, &m.msg.Name, &m.msg.Severity,
	}
	for i := range spans {
		start := p
		p = scanField(input, p, n, start)
		*spans[i] = Span{start, p}
		if i < 5 {
			if p >= n || input[p] != '|' {
				return p, newParseError(p, ErrIncompleteHeader)
			}
			p++
		}
	}
	return p, nil
}

// scanField scans forward in input[p:n] for the next unescaped '|', returning
// its position. If no '|' is found, returns n.
func scanField(input []byte, p, n, start uint32) uint32 {
	for {
		idx := bytes.IndexByte(input[p:n], '|')
		if idx < 0 {
			return n
		}
		p += toU32(idx)
		// Count preceding backslashes to detect escaped pipes.
		bs := uint32(0)
		for j := p; j > start && input[j-1] == '\\'; j-- {
			bs++
		}
		if bs%2 == 1 {
			p++
			continue
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
