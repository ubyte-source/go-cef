package cef

import (
	"bytes"
	"iter"
	"slices"
	"strconv"
	"strings"
)

// MaxExtensions is the hard limit on extension key-value pairs per event.
// The extension array is inlined in [Event]; use [WithMaxExtensions] to reduce
// the effective limit at runtime.
const MaxExtensions = 64

// Version is the CEF format version parsed from the "CEF:N" prefix.
type Version int

// InvalidVersion indicates the version field could not be parsed.
const InvalidVersion Version = -1

// String returns the decimal representation. Fast path for 0 and 1.
func (v Version) String() string {
	switch v {
	case 0:
		return "0"
	case 1:
		return "1"
	default:
		return strconv.Itoa(int(v))
	}
}

// Parser is a reusable CEF parser.
//
// Not safe for concurrent use. The *Event returned by [Parser.Parse] is valid
// until the next Parse call; use [Event.Clone] to retain a copy.
type Parser struct {
	// parseErr and msg are placed first: both contain pointer fields
	// (error interface and []byte respectively), minimizing GC pointer bytes.
	parseErr      ParseError
	msg           Event
	bestEffort    bool
	maxExtensions int
}

// ParserOption configures a [Parser].
type ParserOption func(*Parser)

// NewParser creates a new CEF parser.
func NewParser(opts ...ParserOption) *Parser {
	m := &Parser{
		maxExtensions: MaxExtensions,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithBestEffort enables best-effort mode: partial results are returned
// alongside errors.
func WithBestEffort() ParserOption {
	return func(m *Parser) {
		m.bestEffort = true
	}
}

// WithMaxExtensions limits the number of extensions parsed.
// n must be in [1, MaxExtensions]; panics otherwise.
func WithMaxExtensions(n int) ParserOption {
	if n < 1 || n > MaxExtensions {
		panic("cef: WithMaxExtensions: n (" + strconv.Itoa(n) + ") out of range [1, " + strconv.Itoa(MaxExtensions) + "]")
	}
	return func(m *Parser) {
		m.maxExtensions = n
	}
}

// Span identifies a substring in the original buffer: [Start, End).
type Span struct {
	Start uint32
	End   uint32
}

// Len returns the length. Returns 0 if inverted.
func (s Span) Len() uint32 {
	if s.End < s.Start {
		return 0
	}
	return s.End - s.Start
}

// IsEmpty returns true if the span has no content.
func (s Span) IsEmpty() bool {
	return s.Start >= s.End
}

// String returns a debug representation "[Start:End]".
func (s Span) String() string {
	return "[" + strconv.FormatUint(uint64(s.Start), 10) + ":" + strconv.FormatUint(uint64(s.End), 10) + "]"
}

// ExtPair is a key-value pair in the extension section.
type ExtPair struct {
	Key   Span
	Value Span
}

// String returns a debug representation.
func (p ExtPair) String() string {
	return p.Key.String() + "=" + p.Value.String()
}

// Event is the result of parsing a CEF message. All fields are [Span]
// offsets into the original input buffer — no strings are copied.
//
// The Event holds a reference to the original input; the buffer cannot be
// GC'd while the Event is alive. For long-lived events, use [Event.Clone].
//
// Copying an Event by value shares the underlying buffer with the
// original. Use [Event.Clone] or [Event.CloneTo] for independent copies.
//
// The struct is approximately 1.1 KiB due to the inlined extension array
// ([MaxExtensions] × 16 bytes). Keep this in mind when sizing stack frames
// or embedding Event in other structures.
type Event struct {
	// raw is placed first to minimize GC pointer bytes in the struct layout.
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

	exts [MaxExtensions]ExtPair
}

// Valid returns true if the header was fully parsed.
func (e *Event) Valid() bool {
	return e.headerComplete
}

// Reset clears the Event to its zero value.
func (e *Event) Reset() {
	e.Version = InvalidVersion
	e.Vendor = Span{}
	e.Product = Span{}
	e.DevVersion = Span{}
	e.ClassID = Span{}
	e.Name = Span{}
	e.Severity = Span{}
	e.ExtCount = 0
	e.raw = nil
	e.headerComplete = false
}

// Bytes returns the raw bytes for the given Span.
// Returns nil if out of range.
func (e *Event) Bytes(s Span) []byte {
	if e.raw == nil || int(s.End) > len(e.raw) || s.Start > s.End {
		return nil
	}
	return e.raw[s.Start:s.End]
}

// Text returns a string for the given Span.
// Returns "" if out of range.
func (e *Event) Text(s Span) string {
	if e.raw == nil || int(s.End) > len(e.raw) || s.Start > s.End {
		return ""
	}
	return string(e.raw[s.Start:s.End])
}

// AppendBytes appends the raw bytes for Span s to dst and returns the
// extended buffer. Zero-alloc when dst has sufficient capacity.
func (e *Event) AppendBytes(dst []byte, s Span) []byte {
	if e.raw == nil || int(s.End) > len(e.raw) || s.Start > s.End {
		return dst
	}
	return append(dst, e.raw[s.Start:s.End]...)
}

// Ext looks up an extension by key ([]byte). Zero-alloc.
// For string keys, prefer [Event.ExtString] which benefits from compiler
// optimizations and is typically faster.
func (e *Event) Ext(key []byte) (Span, bool) {
	if e.raw == nil {
		return Span{}, false
	}
	for i := range e.exts[:e.ExtCount] {
		k := e.exts[i].Key
		if bytes.Equal(e.raw[k.Start:k.End], key) {
			return e.exts[i].Value, true
		}
	}
	return Span{}, false
}

// ExtString looks up an extension by key (string). Zero-alloc.
func (e *Event) ExtString(key string) (Span, bool) {
	if e.raw == nil {
		return Span{}, false
	}
	for i := range e.exts[:e.ExtCount] {
		k := e.exts[i].Key
		if string(e.raw[k.Start:k.End]) == key {
			return e.exts[i].Value, true
		}
	}
	return Span{}, false
}

// ExtAt returns the i-th extension pair, or false if out of range.
func (e *Event) ExtAt(i int) (ExtPair, bool) {
	if i < 0 || i >= e.ExtCount {
		return ExtPair{}, false
	}
	return e.exts[i], true
}

// All returns an iterator over extension key-value pairs.
//
// Allocates: ~40 B / 3 allocs per call due to the range-over-func protocol.
// For zero-alloc iteration, use [Event.ExtAt] in a loop.
func (e *Event) All() iter.Seq2[Span, Span] {
	return func(yield func(Span, Span) bool) {
		for i := range e.exts[:e.ExtCount] {
			if !yield(e.exts[i].Key, e.exts[i].Value) {
				return
			}
		}
	}
}

// Clone returns a deep copy independent of the original input buffer.
// Only the referenced byte range is copied, not the entire buffer.
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
// Returns dst for chaining. After warmup, zero allocations.
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

// usedRange returns [lo, hi) covering all non-empty Spans.
func (e *Event) usedRange() (lo, hi uint32) {
	if e.raw == nil {
		return 0, 0
	}
	lo = safeU32(len(e.raw))
	hi = 0
	for _, s := range [...]Span{e.Vendor, e.Product, e.DevVersion, e.ClassID, e.Name, e.Severity} {
		if !s.IsEmpty() {
			lo = min(lo, s.Start)
			hi = max(hi, s.End)
		}
	}
	if e.ExtCount > 0 {
		lo = min(lo, e.exts[0].Key.Start)
		hi = max(hi, e.exts[e.ExtCount-1].Value.End)
	}
	if lo >= hi {
		return 0, 0
	}
	return lo, hi
}

// rebase shifts all Spans by subtracting offset. Skips empty spans.
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
	for i := range e.exts[:e.ExtCount] {
		e.exts[i].Key.Start -= offset
		e.exts[i].Key.End -= offset
		e.exts[i].Value.Start -= offset
		e.exts[i].Value.End -= offset
	}
}

// appendHeader writes the "CEF:ver|...|sev|" portion to dst.
func (e *Event) appendHeader(dst []byte) []byte {
	dst = append(dst, "CEF:"...)
	dst = strconv.AppendInt(dst, int64(e.Version), 10)
	for _, s := range [...]Span{e.Vendor, e.Product, e.DevVersion, e.ClassID, e.Name, e.Severity} {
		dst = append(dst, '|')
		if b := e.Bytes(s); b != nil {
			dst = append(dst, b...)
		}
	}
	dst = append(dst, '|')
	return dst
}

// appendExtensions writes "key=val key2=val2" to dst.
func (e *Event) appendExtensions(dst []byte) []byte {
	for i := range e.exts[:e.ExtCount] {
		if i > 0 {
			dst = append(dst, ' ')
		}
		if b := e.Bytes(e.exts[i].Key); b != nil {
			dst = append(dst, b...)
		}
		dst = append(dst, '=')
		if b := e.Bytes(e.exts[i].Value); b != nil {
			dst = append(dst, b...)
		}
	}
	return dst
}

// AppendText implements [encoding.TextAppender]. Appends the canonical CEF
// representation to dst. Escape sequences are preserved as-is.
func (e *Event) AppendText(dst []byte) ([]byte, error) {
	if e.raw == nil {
		return dst, nil
	}
	n := e.estimateTextLen()
	dst = slices.Grow(dst, n)
	dst = e.appendHeader(dst)
	dst = e.appendExtensions(dst)
	return dst, nil
}

func (e *Event) estimateTextLen() int {
	vlen := versionDigits(e.Version)
	n := 4 + vlen // "CEF:" + version
	for _, s := range [...]Span{e.Vendor, e.Product, e.DevVersion, e.ClassID, e.Name, e.Severity} {
		n += 1 + int(s.Len())
	}
	n++ // trailing "|"
	for i := range e.exts[:e.ExtCount] {
		if i > 0 {
			n++
		}
		n += int(e.exts[i].Key.Len()) + 1 + int(e.exts[i].Value.Len())
	}
	return n
}

// versionDigits returns the number of decimal digits for a version number.
// Avoids allocating a string representation.
func versionDigits(v Version) int {
	switch {
	case v < 10:
		return 1
	case v < 100:
		return 2
	case v < 1000:
		return 3
	default:
		return 4
	}
}

// MarshalText implements [encoding.TextMarshaler].
// Allocates: one buffer proportional to the serialized size.
// Returns (nil, nil) if the Event has no backing buffer.
func (e *Event) MarshalText() ([]byte, error) {
	return e.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler]. Copies the input
// (required by the interface contract) and parses it.
// Allocates: one copy of the input buffer plus one [ParseError] on error.
// For zero-alloc parsing, use [Parser.Parse] directly.
func (e *Event) UnmarshalText(text []byte) error {
	buf := bytes.Clone(text)
	// Stack-allocated Parser to avoid heap escape.
	// Must be kept in sync with NewParser defaults.
	var m Parser
	m.maxExtensions = MaxExtensions
	parsed, err := m.Parse(buf)
	if err != nil {
		return err
	}
	*e = *parsed
	return nil
}

// String returns a human-readable summary for debugging.
// Allocates: one string via [strings.Builder].
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
		b.WriteString(e.Text(e.exts[i].Key))
		b.WriteByte('=')
		v := e.Text(e.exts[i].Value)
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
