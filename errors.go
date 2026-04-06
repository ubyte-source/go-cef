package cef

import "strconv"

// constError is a string-based error type that can be declared as a const.
type constError string

func (e constError) Error() string { return string(e) }

// Sentinel errors for CEF parsing failures. Use [errors.Is] to check.
const (
	ErrEmpty            = constError("empty input")
	ErrPrefix           = constError("expecting CEF: prefix")
	ErrVersion          = constError("expecting a numeric version after CEF:")
	ErrIncompleteHeader = constError("incomplete CEF header")
	ErrExtKey           = constError("invalid extension key")
	ErrExtOverflow      = constError("extension count exceeds maximum")
	ErrInputTooLarge    = constError("input exceeds maximum size (4 GiB)")
)

// SeverityUnknown is returned by [Event.SeverityNum] for the CEF keyword "Unknown".
const SeverityUnknown = -1

// ParseError is a parsing error with byte offset.
type ParseError struct {
	Err      error
	Position uint32
}

// Error returns a human-readable message including the byte offset.
func (e *ParseError) Error() string {
	return e.Err.Error() + " [col " + strconv.FormatUint(uint64(e.Position), 10) + "]"
}

// Unwrap returns the underlying sentinel error for use with [errors.Is].
func (e *ParseError) Unwrap() error {
	return e.Err
}

// makeError reuses the preallocated ParseError in the Parser.
// The returned pointer is valid until the next Parse call.
func (m *Parser) makeError(pos uint32, sentinel error) *ParseError {
	m.parseErr.Err = sentinel
	m.parseErr.Position = pos
	return &m.parseErr
}
