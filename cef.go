package cef

import (
	"bytes"
	"encoding/binary"
	"errors"
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
)

// MaxExtensions is the hard cap on extension key-value pairs per event.
const MaxExtensions = 64

// Version is the CEF format version parsed from the "CEF:N" prefix.
type Version int

// InvalidVersion marks a version that could not be parsed.
const InvalidVersion Version = -1

// String returns the decimal representation.
func (v Version) String() string {
	switch v {
	case 0:
		return "0"
	case 1:
		return "1"
	}
	return strconv.Itoa(int(v))
}

// Parser is a reusable CEF parser. Not safe for concurrent use.
// The *Event returned by Parse is valid until the next Parse call.
type Parser struct {
	parseErr      ParseError
	msg           Event
	bestEffort    bool
	maxExtensions int
}

// ParserOption configures a Parser.
type ParserOption func(*Parser)

// NewParser creates a new CEF parser.
func NewParser(opts ...ParserOption) *Parser {
	p := &Parser{maxExtensions: MaxExtensions}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithBestEffort enables best-effort mode: partial results are returned
// alongside errors.
func WithBestEffort() ParserOption {
	return func(p *Parser) { p.bestEffort = true }
}

// WithMaxExtensions caps the number of extensions parsed.
// n must be in [1, MaxExtensions]; panics otherwise.
func WithMaxExtensions(n int) ParserOption {
	if n < 1 || n > MaxExtensions {
		panic("cef: WithMaxExtensions: n out of range [1, " + strconv.Itoa(MaxExtensions) + "]")
	}
	return func(p *Parser) { p.maxExtensions = n }
}

// Span identifies a substring in the original buffer: [Start, End).
type Span struct {
	Start uint32
	End   uint32
}

// Len returns the length, or 0 if inverted.
func (s Span) Len() uint32 {
	if s.End < s.Start {
		return 0
	}
	return s.End - s.Start
}

// IsEmpty reports whether the span has no content.
func (s Span) IsEmpty() bool { return s.Start >= s.End }

// String returns a debug representation "[Start:End]".
func (s Span) String() string {
	var buf [24]byte
	b := strconv.AppendUint(buf[:0], uint64(s.Start), 10)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(s.End), 10)
	return "[" + string(b) + "]"
}

// ExtPair is a key-value pair in the extension section.
type ExtPair struct {
	Key   Span
	Value Span
}

// String returns a debug representation.
func (p ExtPair) String() string { return p.Key.String() + "=" + p.Value.String() }

// Event is the result of parsing a CEF message. All fields are Span
// offsets into the original input buffer — no strings are copied.
// Copying an Event by value shares the underlying buffer.
type Event struct {
	raw []byte

	Version    Version
	Vendor     Span
	Product    Span
	DevVersion Span
	ClassID    Span
	Name       Span
	Severity   Span

	ExtCount       int
	headerComplete bool

	extKeys  [MaxExtensions]Span
	extVals  [MaxExtensions]Span
	extPacks [MaxExtensions]uint32
}

// Valid reports whether the header was fully parsed.
func (e *Event) Valid() bool { return e.headerComplete }

// Reset clears the Event to its zero state.
func (e *Event) Reset() {
	e.raw = nil
	e.Version = InvalidVersion
	e.Vendor = Span{}
	e.Product = Span{}
	e.DevVersion = Span{}
	e.ClassID = Span{}
	e.Name = Span{}
	e.Severity = Span{}
	e.ExtCount = 0
	e.headerComplete = false
}

// Bytes returns the raw bytes for the given Span, or nil if out of range.
func (e *Event) Bytes(s Span) []byte {
	if e.raw == nil || int(s.End) > len(e.raw) || s.Start > s.End {
		return nil
	}
	return e.raw[s.Start:s.End]
}

// Text returns a string for the given Span, or "" if out of range.
func (e *Event) Text(s Span) string {
	if e.raw == nil || int(s.End) > len(e.raw) || s.Start > s.End {
		return ""
	}
	return string(e.raw[s.Start:s.End])
}

// AppendBytes appends the raw bytes for Span s to dst.
// Zero-alloc when dst has sufficient capacity.
func (e *Event) AppendBytes(dst []byte, s Span) []byte {
	if e.raw == nil || int(s.End) > len(e.raw) || s.Start > s.End {
		return dst
	}
	return append(dst, e.raw[s.Start:s.End]...)
}

// Ext looks up an extension by byte-slice key. Zero-alloc.
func (e *Event) Ext(key []byte) (Span, bool) {
	if e.raw == nil || len(key) == 0 {
		return Span{}, false
	}
	pack := keyPackBytes(key)
	keyLen := uint32(len(key) & math.MaxUint32)
	for i := range e.ExtCount {
		if e.extPacks[i] != pack {
			continue
		}
		k := e.extKeys[i]
		if k.End-k.Start != keyLen {
			continue
		}
		if keyLen <= 4 || bytes.Equal(e.raw[k.Start+4:k.End], key[4:]) {
			return e.extVals[i], true
		}
	}
	return Span{}, false
}

// ExtString looks up an extension by string key. Zero-alloc.
func (e *Event) ExtString(key string) (Span, bool) {
	if e.raw == nil || key == "" {
		return Span{}, false
	}
	pack := keyPackString(key)
	keyLen := uint32(len(key) & math.MaxUint32)
	for i := range e.ExtCount {
		if e.extPacks[i] != pack {
			continue
		}
		k := e.extKeys[i]
		if k.End-k.Start != keyLen {
			continue
		}
		if keyLen <= 4 || string(e.raw[k.Start+4:k.End]) == key[4:] {
			return e.extVals[i], true
		}
	}
	return Span{}, false
}

// ExtAt returns the i-th extension pair.
func (e *Event) ExtAt(i int) (ExtPair, bool) {
	if i < 0 || i >= e.ExtCount {
		return ExtPair{}, false
	}
	return ExtPair{Key: e.extKeys[i], Value: e.extVals[i]}, true
}

// All returns an iterator over extension key-value pairs.
// Allocates ~40 B per call due to the iter.Seq2 protocol;
// use ExtAt in a loop for zero-alloc iteration.
func (e *Event) All() iter.Seq2[Span, Span] {
	return func(yield func(Span, Span) bool) {
		for i := range e.ExtCount {
			if !yield(e.extKeys[i], e.extVals[i]) {
				return
			}
		}
	}
}

// Clone returns a deep copy independent of the original input buffer.
// Only the referenced byte range is copied.
func (e *Event) Clone() *Event {
	c := new(Event)
	*c = *e
	lo, hi := e.usedRange()
	if lo >= hi {
		c.raw = nil
		return c
	}
	c.raw = make([]byte, hi-lo)
	copy(c.raw, e.raw[lo:hi])
	c.rebase(lo)
	return c
}

// CloneTo copies the event into dst, reusing dst's raw buffer when possible.
// Returns dst for chaining. Zero allocations after warmup.
func (e *Event) CloneTo(dst *Event) *Event {
	lo, hi := e.usedRange()
	raw := dst.raw
	*dst = *e
	needed := int(hi - lo)
	if needed == 0 {
		dst.raw = nil
		return dst
	}
	if cap(raw) >= needed {
		dst.raw = raw[:needed]
	} else {
		dst.raw = make([]byte, needed)
	}
	copy(dst.raw, e.raw[lo:hi])
	dst.rebase(lo)
	return dst
}

func (e *Event) usedRange() (lo, hi uint32) {
	if e.raw == nil {
		return 0, 0
	}
	lo = uint32(len(e.raw) & math.MaxUint32)
	hi = 0
	hs := [6]Span{e.Vendor, e.Product, e.DevVersion, e.ClassID, e.Name, e.Severity}
	for _, s := range hs {
		if s.IsEmpty() {
			continue
		}
		if s.Start < lo {
			lo = s.Start
		}
		if s.End > hi {
			hi = s.End
		}
	}
	if e.ExtCount > 0 {
		if e.extKeys[0].Start < lo {
			lo = e.extKeys[0].Start
		}
		if end := e.extVals[e.ExtCount-1].End; end > hi {
			hi = end
		}
	}
	if lo >= hi {
		return 0, 0
	}
	return lo, hi
}

func (e *Event) rebase(offset uint32) {
	if offset == 0 {
		return
	}
	for _, s := range [...]*Span{&e.Vendor, &e.Product, &e.DevVersion, &e.ClassID, &e.Name, &e.Severity} {
		if s.IsEmpty() {
			continue
		}
		s.Start -= offset
		s.End -= offset
	}
	for i := range e.ExtCount {
		e.extKeys[i].Start -= offset
		e.extKeys[i].End -= offset
		e.extVals[i].Start -= offset
		e.extVals[i].End -= offset
	}
}

func (e *Event) appendHeader(dst []byte) []byte {
	dst = append(dst, "CEF:"...)
	dst = strconv.AppendInt(dst, int64(e.Version), 10)
	hs := [6]Span{e.Vendor, e.Product, e.DevVersion, e.ClassID, e.Name, e.Severity}
	for _, s := range hs {
		dst = append(dst, '|')
		if b := e.Bytes(s); b != nil {
			dst = append(dst, b...)
		}
	}
	return append(dst, '|')
}

func (e *Event) appendExtensions(dst []byte) []byte {
	for i := range e.ExtCount {
		if i > 0 {
			dst = append(dst, ' ')
		}
		if b := e.Bytes(e.extKeys[i]); b != nil {
			dst = append(dst, b...)
		}
		dst = append(dst, '=')
		if b := e.Bytes(e.extVals[i]); b != nil {
			dst = append(dst, b...)
		}
	}
	return dst
}

// AppendText appends the canonical CEF representation to dst.
// Escape sequences are preserved as-is.
func (e *Event) AppendText(dst []byte) ([]byte, error) {
	if e.raw == nil {
		return dst, nil
	}
	dst = slices.Grow(dst, e.estimateTextLen())
	dst = e.appendHeader(dst)
	return e.appendExtensions(dst), nil
}

func (e *Event) estimateTextLen() int {
	n := 4 + versionDigits(e.Version)
	hs := [6]Span{e.Vendor, e.Product, e.DevVersion, e.ClassID, e.Name, e.Severity}
	for _, s := range hs {
		n += 1 + int(s.Len())
	}
	n++
	for i := range e.ExtCount {
		if i > 0 {
			n++
		}
		n += int(e.extKeys[i].Len()) + 1 + int(e.extVals[i].Len())
	}
	return n
}

func versionDigits(v Version) int {
	switch {
	case v < 0:
		return 2
	case v < 10:
		return 1
	case v < 100:
		return 2
	case v < 1000:
		return 3
	}
	return 4
}

// MarshalText implements encoding.TextMarshaler.
func (e *Event) MarshalText() ([]byte, error) { return e.AppendText(nil) }

// UnmarshalText implements encoding.TextUnmarshaler. Copies the input
// and parses it. For zero-alloc parsing, use Parser.Parse directly.
func (e *Event) UnmarshalText(text []byte) error {
	buf := bytes.Clone(text)
	var p Parser
	p.maxExtensions = MaxExtensions
	parsed, err := p.Parse(buf)
	if err != nil {
		var pe *ParseError
		if errors.As(err, &pe) {
			cp := *pe
			return &cp
		}
		return err
	}
	*e = *parsed
	return nil
}

// String returns a human-readable summary.
func (e *Event) String() string {
	if e.raw == nil {
		return "Event{}"
	}
	var b strings.Builder
	b.Grow(256)
	b.WriteString("Event{ver=")
	b.WriteString(e.Version.String())
	b.WriteString(" vendor=")
	b.WriteString(e.Text(e.Vendor))
	b.WriteString(" product=")
	b.WriteString(e.Text(e.Product))
	b.WriteString(" devver=")
	b.WriteString(e.Text(e.DevVersion))
	b.WriteString(" classid=")
	b.WriteString(e.Text(e.ClassID))
	b.WriteString(" name=")
	b.WriteString(e.Text(e.Name))
	b.WriteString(" sev=")
	b.WriteString(e.Text(e.Severity))
	b.WriteString(" exts=")
	b.WriteString(strconv.Itoa(e.ExtCount))
	e.writeExtSample(&b)
	b.WriteByte('}')
	return b.String()
}

func (e *Event) writeExtSample(b *strings.Builder) {
	if e.ExtCount == 0 {
		return
	}
	const maxShow = 3
	const maxVal = 30
	b.WriteByte('[')
	n := min(e.ExtCount, maxShow)
	for i := range n {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(e.Text(e.extKeys[i]))
		b.WriteByte('=')
		v := e.Text(e.extVals[i])
		if len(v) > maxVal {
			b.WriteString(v[:maxVal])
			b.WriteString("...")
		} else {
			b.WriteString(v)
		}
	}
	if e.ExtCount > maxShow {
		b.WriteString(" ...")
	}
	b.WriteByte(']')
}

// keyPackBytes packs up to the first 4 bytes of key into a uint32.
// Single-instruction equality pre-filter for extension lookup.
func keyPackBytes(key []byte) uint32 {
	n := len(key)
	if n >= 4 {
		return binary.LittleEndian.Uint32(key)
	}
	var h uint32
	for i := range n {
		h |= uint32(key[i]) << (i * 8)
	}
	return h
}

func keyPackString(key string) uint32 {
	n := len(key)
	if n >= 4 {
		return uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	}
	var h uint32
	for i := range n {
		h |= uint32(key[i]) << (i * 8)
	}
	return h
}
