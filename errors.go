package cef

import (
	"strconv"
	"strings"
)

type constError string

func (e constError) Error() string { return string(e) }

// Sentinel errors for CEF parsing failures. Use errors.Is to check.
const (
	ErrEmpty            = constError("empty input")
	ErrPrefix           = constError("expecting CEF: prefix")
	ErrVersion          = constError("expecting a numeric version after CEF:")
	ErrIncompleteHeader = constError("incomplete CEF header")
	ErrExtKey           = constError("invalid extension key")
	ErrExtOverflow      = constError("extension count exceeds maximum")
	ErrInputTooLarge    = constError("input exceeds maximum size (4 GiB)")
)

// SeverityUnknown is returned by Event.SeverityNum for the CEF keyword "Unknown".
const SeverityUnknown = -1

// ParseError is a parsing error with byte offset.
type ParseError struct {
	Err      error
	Position uint32
}

// Error returns a human-readable message including the byte offset.
func (e *ParseError) Error() string {
	msg := e.Err.Error()
	var b strings.Builder
	b.Grow(len(msg) + 16)
	b.WriteString(msg)
	b.WriteString(" [col ")
	var buf [10]byte
	b.Write(strconv.AppendUint(buf[:0], uint64(e.Position), 10))
	b.WriteByte(']')
	return b.String()
}

// Unwrap returns the underlying sentinel error for use with errors.Is.
func (e *ParseError) Unwrap() error { return e.Err }

func (p *Parser) makeError(pos uint32, sentinel error) *ParseError {
	p.parseErr.Err = sentinel
	p.parseErr.Position = pos
	return &p.parseErr
}
