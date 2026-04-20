package cef

import (
	"bytes"
	"math"
)

func (p *Parser) fail(pe *ParseError) (*Event, error) {
	if p.bestEffort {
		return &p.msg, pe
	}
	return nil, pe
}

// Parse parses the input as a CEF message.
// The returned *Event is valid until the next Parse call on the same Parser.
func (p *Parser) Parse(input []byte) (*Event, error) {
	p.resetMsg(input)

	if len(input) == 0 {
		return p.fail(p.makeError(0, ErrEmpty))
	}
	if len(input) > math.MaxUint32 {
		return p.fail(p.makeError(0, ErrInputTooLarge))
	}
	n := uint32(len(input) & math.MaxUint32)

	pos, err := p.parseVersion(input, n)
	if err != nil {
		return p.fail(err)
	}

	pos, err = p.parseHeaderFields(input, pos, n)
	if err != nil {
		return p.fail(err)
	}

	p.msg.headerComplete = true

	if pos < n && input[pos] == '|' {
		if extErr := p.parseExtensions(pos + 1); extErr != nil {
			return p.fail(extErr)
		}
	}

	return &p.msg, nil
}

func (p *Parser) resetMsg(input []byte) {
	p.msg.raw = input
	p.msg.Version = InvalidVersion
	p.msg.Vendor = Span{}
	p.msg.Product = Span{}
	p.msg.DevVersion = Span{}
	p.msg.ClassID = Span{}
	p.msg.Name = Span{}
	p.msg.Severity = Span{}
	p.msg.ExtCount = 0
	p.msg.headerComplete = false
}

func skipSpaces(input []byte, p, n uint32) uint32 {
	for p < n && input[p] == ' ' {
		p++
	}
	return p
}

func scanDigits(input []byte, p, n uint32) uint32 {
	for p < n && input[p] >= '0' && input[p] <= '9' {
		p++
	}
	return p
}

func (p *Parser) parseVersion(input []byte, n uint32) (uint32, *ParseError) {
	if n < 4 || string(input[:4]) != "CEF:" {
		return 0, p.makeError(0, ErrPrefix)
	}
	pos := skipSpaces(input, 4, n)

	if pos >= n || input[pos] < '0' || input[pos] > '9' {
		return pos, p.makeError(pos, ErrVersion)
	}
	vStart := pos
	pos = scanDigits(input, pos, n)
	p.msg.Version = parseVersionBytes(input[vStart:pos])
	if p.msg.Version < 0 {
		return vStart, p.makeError(vStart, ErrVersion)
	}

	if pos >= n || input[pos] != '|' {
		return pos, p.makeError(pos, ErrIncompleteHeader)
	}
	return pos + 1, nil
}

func (p *Parser) parseHeaderFields(input []byte, pos, n uint32) (uint32, *ParseError) {
	targets := [6]*Span{
		&p.msg.Vendor, &p.msg.Product, &p.msg.DevVersion,
		&p.msg.ClassID, &p.msg.Name, &p.msg.Severity,
	}
	for i, field := range targets {
		start := pos
		pos = scanField(input, pos, n)
		*field = Span{start, pos}
		if i == 5 {
			break
		}
		if pos >= n || input[pos] != '|' {
			return pos, p.makeError(pos, ErrIncompleteHeader)
		}
		pos++
	}
	return pos, nil
}

// scanField returns the next unescaped '|' position in input[pos:n], or n.
func scanField(input []byte, pos, n uint32) uint32 {
	start := pos
	for pos < n {
		idx := bytes.IndexByte(input[pos:n], '|')
		if idx < 0 {
			return n
		}
		q := pos + uint32(idx&math.MaxUint32)
		if !isEscapedDelim(input, q, start) {
			return q
		}
		pos = q + 1
	}
	return n
}

// isEscapedDelim reports whether input[at] is preceded by an odd number of
// backslashes (i.e., it is escaped). minPos bounds the backward scan.
func isEscapedDelim(input []byte, at, minPos uint32) bool {
	if at <= minPos || input[at-1] != '\\' {
		return false
	}
	bs := uint32(1)
	for j := at - 1; j > minPos && input[j-1] == '\\'; j-- {
		bs++
	}
	return bs&1 == 1
}

// parseVersionBytes parses 1-4 ASCII digits; rejects leading zeros except "0".
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
