package cef

import (
	"strconv"
	"strings"
)

// errPrefix starts the text of every error the package declares.
const errPrefix = "cef: "

// constError is the type of the sentinels: constants that compare by value.
type constError string

// Error returns the text of e.
func (e constError) Error() string { return string(e) }

// The faults Parse wraps in a *ParseError and the text methods return; match them
// with errors.Is.
const (
	// ErrEmpty reports an input of no bytes.
	ErrEmpty = constError(errPrefix + "empty input")
	// ErrPrefix reports an input that does not start with "CEF:".
	ErrPrefix = constError(errPrefix + "expecting CEF: prefix")
	// ErrVersion reports a version token that is not 1 to 4 digits without a leading zero.
	ErrVersion = constError(errPrefix + "version is not 1 to 4 digits without a leading zero")
	// ErrIncompleteHeader reports a header without its seventh unescaped '|', and an
	// Event whose HeaderComplete is false, given to AppendText or MarshalText.
	ErrIncompleteHeader = constError(errPrefix + "incomplete CEF header")
	// ErrExtKey reports an extension that holds no '=' or whose first key is not one or
	// more key bytes.
	ErrExtKey = constError(errPrefix + "invalid extension key")
	// ErrExtOverflow reports a pair past the limit Parse was given, and an Event of more
	// than MaxExtensions pairs, or whose last value a cut at a pair limit left ending in a
	// space, CR or LF, given to AppendText or MarshalText.
	ErrExtOverflow = constError(errPrefix + "extension count exceeds maximum")
	// ErrInputTooLarge reports an input longer than 4294967295 bytes, the most a Span
	// indexes.
	ErrInputTooLarge = constError(errPrefix + "input longer than 4294967295 bytes")
	// ErrInvalidUTF8 reports an Event whose text is not UTF-8, given to AppendText or
	// MarshalText.
	ErrInvalidUTF8 = constError(errPrefix + "event text is not UTF-8")
)

// ParseError is a fault of Parse: Err, the sentinel, and Position, the zero-based byte
// offset where Parse found it. Error and Unwrap need Err, which the zero value lacks;
// nothing writes a ParseError Parse returned, so readers may share it.
type ParseError struct {
	Err      error
	Position uint32
}

// Error returns Err's text and the offset, as "cef: incomplete CEF header at byte 19";
// one allocation.
func (e *ParseError) Error() string {
	text := e.Err.Error()
	var b strings.Builder
	b.Grow(len(text) + len(positionText) + maxPositionDigits)
	b.WriteString(text)
	b.WriteString(positionText)
	var digits [maxPositionDigits]byte
	b.Write(strconv.AppendUint(digits[:0], uint64(e.Position), decimal))
	return b.String()
}

// Unwrap returns Err, so errors.Is matches the sentinel.
func (e *ParseError) Unwrap() error { return e.Err }

// Shape of the text Error appends to Err's: the words before the offset, and the
// digits of the largest offset.
const (
	positionText      = " at byte "
	maxPositionDigits = len("4294967295")
)

// fault returns a fresh *ParseError for the sentinel err at the input position pos.
func fault(pos int, err constError) error {
	return &ParseError{Err: err, Position: offset(pos)}
}
