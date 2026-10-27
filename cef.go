package cef

import (
	"encoding/binary"
	"iter"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Version is a CEF version: 1 to 4 decimal digits without a leading zero, 0 to 9999.
type Version int

// String returns v in decimal; no allocation for 0 to 99.
func (v Version) String() string { return strconv.Itoa(int(v)) }

// Span is the byte range [Start, End) of an event's bytes; an Event method reads a Span
// that does not lie within those bytes as empty.
type Span struct {
	Start uint32
	End   uint32
}

// Len returns End - Start, or 0 when s is inverted.
func (s Span) Len() uint32 {
	if s.End < s.Start {
		return 0
	}
	return s.End - s.Start
}

// IsEmpty reports whether s covers no byte, an inverted s included.
func (s Span) IsEmpty() bool { return s.Start >= s.End }

// String returns s as "[Start:End]"; one allocation.
func (s Span) String() string {
	var buf [spanTextLen]byte
	return string(s.appendText(buf[:0]))
}

// spanTextLen is the length of the longest text of a Span.
const spanTextLen = len("[4294967295:4294967295]")

// appendText appends the text String returns to dst.
func (s Span) appendText(dst []byte) []byte {
	dst = append(dst, '[')
	dst = strconv.AppendUint(dst, uint64(s.Start), decimal)
	dst = append(dst, ':')
	dst = strconv.AppendUint(dst, uint64(s.End), decimal)
	return append(dst, ']')
}

// ExtPair is one extension pair: the key span and the raw value span.
type ExtPair struct {
	Key   Span
	Value Span
}

// String returns the two spans as "[Start:End]=[Start:End]"; one allocation.
func (p ExtPair) String() string {
	var buf [2*spanTextLen + 1]byte
	b := append(p.Key.appendText(buf[:0]), '=')
	return string(p.Value.appendText(b))
}

// pair is one extension pair of an Event: the key [key, eq), the value [eq+1, end) and
// pack, the first wordLen key bytes as keyPack returns them.
type pair struct {
	key  uint32
	eq   uint32
	end  uint32
	pack uint32
}

func (p *pair) keySpan() Span { return Span{Start: p.key, End: p.eq} }

func (p *pair) valueSpan() Span { return Span{Start: p.eq + 1, End: p.end} }

// Indexes of the header fields in Event.header, in input order.
const (
	fieldDeviceVendor = iota
	fieldDeviceProduct
	fieldDeviceVersion
	fieldDeviceEventClassID
	fieldName
	fieldSeverity
	headerFields
)

// Event is one parsed event: the version, and the six header fields and extension pairs
// as Spans of the bytes it last read; its zero value is an empty event ready for Parse.
type Event struct {
	raw     []byte // the bytes the spans index: the input of Parse, or bytes of owned
	owned   []byte // bytes e owns, which only Clone, CloneTo and UnmarshalText write
	pairs   []pair
	header  [headerFields]Span
	version uint16

	headerComplete bool
}

// HeaderComplete reports whether the last Parse read the whole header, seventh '|'
// included, so a fault in the extension leaves it true.
func (e *Event) HeaderComplete() bool { return e.headerComplete }

// Version returns the CEF version, 0 when Parse did not read one.
func (e *Event) Version() Version { return Version(e.version) }

// DeviceVendor returns the span of the Device Vendor field, escapes kept, empty before
// Parse reads it.
func (e *Event) DeviceVendor() Span { return e.header[fieldDeviceVendor] }

// DeviceProduct returns the span of the Device Product field, escapes kept.
func (e *Event) DeviceProduct() Span { return e.header[fieldDeviceProduct] }

// DeviceVersion returns the span of the Device Version field, escapes kept.
func (e *Event) DeviceVersion() Span { return e.header[fieldDeviceVersion] }

// DeviceEventClassID returns the span of the Device Event Class ID field, escapes kept.
func (e *Event) DeviceEventClassID() Span { return e.header[fieldDeviceEventClassID] }

// Name returns the span of the Name field, escapes kept.
func (e *Event) Name() Span { return e.header[fieldName] }

// Severity returns the span of the Severity field, escapes kept.
func (e *Event) Severity() Span { return e.header[fieldSeverity] }

// ExtCount returns the number of extension pairs e holds.
func (e *Event) ExtCount() int { return len(e.pairs) }

// ExtAt returns the i-th pair in input order, and false when i is outside
// [0, ExtCount()).
func (e *Event) ExtAt(i int) (ExtPair, bool) {
	if i < 0 || i >= len(e.pairs) {
		return ExtPair{}, false
	}
	p := &e.pairs[i]
	return ExtPair{Key: p.keySpan(), Value: p.valueSpan()}, true
}

// All yields the key and raw value span of each pair in input order; a range over it
// allocates nothing.
func (e *Event) All() iter.Seq2[Span, Span] {
	return func(yield func(Span, Span) bool) {
		for _, p := range e.pairs {
			if !yield(p.keySpan(), p.valueSpan()) {
				return
			}
		}
	}
}

// Ext returns the raw value span of the last pair whose key equals key, and false when
// none does; no allocation.
func (e *Event) Ext(key []byte) (Span, bool) { return lookup(e, key) }

// ExtString is Ext for a string key.
func (e *Event) ExtString(key string) (Span, bool) { return lookup(e, key) }

// wordLen is the number of bytes of a word, as keyPack reads one.
const wordLen = 4

// lookup returns the value span of the last pair of e whose key is key.
func lookup[T Text](e *Event, key T) (Span, bool) {
	pack, pairs := keyPack(key), e.pairs
	for len(pairs) > 0 {
		last := len(pairs) - 1
		if p := &pairs[last]; p.pack == pack && int(p.eq-p.key) == len(key) &&
			(len(key) <= wordLen || string(e.raw[p.key+wordLen:p.eq]) == string(key[wordLen:])) {
			return p.valueSpan(), true
		}
		pairs = pairs[:last]
	}
	return Span{}, false
}

// decimal is the base in which the package writes numbers.
const decimal = 10

// Shifts of the second to the eighth byte of a little-endian word.
const (
	lane1 = 8
	lane2 = 16
	lane3 = 24
	lane4 = 32
	lane5 = 40
	lane6 = 48
	lane7 = 56
)

// Lanes of a scan word, the scanBytes input bytes a uint64 holds: laneOnes has 1 in
// each byte, laneLow7 its seven low bits and laneHigh its high bit.
const (
	scanBytes = 8
	laneBits  = 8
	laneOnes  = 0x0101010101010101
	laneLow7  = 0x7f * laneOnes
	laneHigh  = 0x80 * laneOnes
)

// zeroLanes returns laneHigh's bit in each byte of w that is zero, and 0 elsewhere.
func zeroLanes(w uint64) uint64 { return ^((w&laneLow7 + laneLow7) | w) & laneHigh }

// keyPack returns the first wordLen bytes of key as a little-endian word, the bytes
// past its end zero.
func keyPack[T Text](key T) uint32 {
	if len(key) >= wordLen {
		return uint32(key[0]) | uint32(key[1])<<lane1 | uint32(key[2])<<lane2 |
			uint32(key[3])<<lane3
	}
	var pack uint32
	for i := len(key) - 1; i >= 0; i-- {
		pack = pack<<lane1 | uint32(key[i])
	}
	return pack
}

// Bytes returns the bytes s covers as a view whose capacity ends at s.End, never nil:
// an empty view of no capacity when s is empty, inverted or ends past the event's
// bytes; no allocation.
func (e *Event) Bytes(s Span) []byte { return view(e.raw, s) }

// view returns the bytes of raw that s covers, capacity capped at s.End, or an empty
// view of no capacity when s is empty, inverted or ends past raw.
func view(raw []byte, s Span) []byte {
	if s.Start >= s.End || uint64(s.End) > uint64(len(raw)) {
		var none [0]byte
		return none[:]
	}
	return raw[s.Start:s.End:s.End]
}

// Text returns string(Bytes(s)): one allocation for a span of two bytes or more, none
// for an empty or one-byte span.
func (e *Event) Text(s Span) string { return string(e.Bytes(s)) }

// AppendBytes appends the bytes s covers to dst, and nothing when s is inverted or ends
// past the event's bytes; no allocation when dst has room.
func (e *Event) AppendBytes(dst []byte, s Span) []byte { return append(dst, e.Bytes(s)...) }

// Clone returns a copy of e that owns its bytes and pairs: one allocation for the
// Event, one for the bytes from its first header field to the end of its last span when
// there are any, and one for its pairs when there are any.
func (e *Event) Clone() *Event { return e.copyTo(new(Event)) }

// CloneTo makes dst, which must not be nil, a copy of e that owns its bytes and pairs,
// and returns it; dst may be e. It writes only dst's pairs and owned bytes, reused with
// no allocation unless too few, or more than 64 KiB for a copy that needs no more.
func (e *Event) CloneTo(dst *Event) *Event { return e.copyTo(dst) }

// AppendText appends e's text or fails with dst unchanged: ErrIncompleteHeader unless
// HeaderComplete, ErrExtOverflow above MaxExtensions pairs or for a last value ending
// in a space, CR or LF, then ErrInvalidUTF8; no allocation when dst has room.
func (e *Event) AppendText(dst []byte) ([]byte, error) {
	if !e.headerComplete {
		return dst, ErrIncompleteHeader
	}
	if len(e.pairs) > MaxExtensions || e.cutTrailing() {
		return dst, ErrExtOverflow
	}
	lo, hi := e.coveredRange(e.pairs)
	if !utf8.Valid(e.raw[lo:hi]) {
		return dst, ErrInvalidUTF8
	}
	fields := e.raw[lo:e.header[fieldSeverity].End]
	var ext []byte
	if len(e.pairs) > 0 {
		ext = e.raw[e.pairs[0].key:hi]
	}
	dst = slices.Grow(dst, len(cefPrefix)+versionLen(e.version)+len(fields)+len(ext)+len("||"))
	dst = append(dst, cefPrefix...)
	dst = strconv.AppendUint(dst, uint64(e.version), decimal)
	dst = append(dst, '|')
	dst = append(dst, fields...)
	dst = append(dst, '|')
	return append(dst, ext...), nil
}

// versionLen returns the number of decimal digits of v.
func versionLen(v uint16) int {
	n := 1
	for ; v >= decimal; v /= decimal {
		n++
	}
	return n
}

// MarshalText returns AppendText(nil), the text UnmarshalText reads back to an Event
// equal to e: one allocation, and nil with AppendText's error on failure.
func (e *Event) MarshalText() ([]byte, error) { return e.AppendText(nil) }

// UnmarshalText copies text into bytes e owns and parses the copy under MaxExtensions,
// keeping the partial event on a fault; it allocates only a fault's *ParseError, and
// bytes or pairs when e's are too few, or over 64 KiB for a text that needs no more.
func (e *Event) UnmarshalText(text []byte) error {
	if !exceedsSpans(len(text)) { // Parse refuses a longer text and keeps none of it
		b := e.ownBytes(len(text))
		copy(b, text)
		text = b
	}
	return e.Parse(text, MaxExtensions)
}

// Reset drops e's reference to its input: e then answers as the zero Event and keeps
// its storage for the next Parse.
func (e *Event) Reset() { e.restart(nil) }

// Limits of the pairs String shows: how many, and the most bytes of each value.
const (
	shownPairs    = 3
	shownValueLen = 30
)

// Fixed parts of String's text.
const (
	summaryOpen   = "Event{ver="
	summaryCount  = " exts="
	summaryMore   = " ..."
	summaryCut    = "..."
	summaryClose  = "}"
	summaryDigits = len("18446744073709551615")
)

// String returns a one-line summary for debugging: the version, the header fields, the
// pair count and the first three pairs, each value cut at 30 bytes and each CR or LF
// written as a space; one allocation.
func (e *Event) String() string {
	labels := [headerFields]string{" vendor=", " product=", " devver=", " classid=", " name=", " sev="}
	shown := e.pairs[:min(len(e.pairs), shownPairs)]
	n := len(summaryOpen) + len(summaryCount) + 2*summaryDigits + len("[]") + len(summaryMore) +
		len(summaryClose)
	var views [headerFields][]byte
	for i, s := range e.header {
		views[i] = e.Bytes(s)
		n += len(labels[i]) + len(views[i])
	}
	for i := range shown {
		n += len(" =") + len(e.Bytes(shown[i].keySpan())) + shownValueLen + len(summaryCut)
	}
	lo, hi := e.coveredRange(nil)
	breaks := hasLineBreak(view(e.raw, Span{Start: offset(lo), End: offset(hi)}))
	var b strings.Builder
	b.Grow(n)
	var digits [summaryDigits]byte
	b.WriteString(summaryOpen)
	b.Write(strconv.AppendUint(digits[:0], uint64(e.version), decimal))
	for i, v := range views {
		b.WriteString(labels[i])
		if breaks {
			writeLine(&b, v)
		} else {
			b.Write(v)
		}
	}
	b.WriteString(summaryCount)
	b.Write(strconv.AppendInt(digits[:0], int64(len(e.pairs)), decimal))
	e.writePairs(&b)
	b.WriteString(summaryClose)
	return b.String()
}

// copyTo makes dst a copy of e that owns its bytes and pairs, and returns it.
func (e *Event) copyTo(dst *Event) *Event {
	lo, hi := e.coveredRange(e.pairs)
	b := dst.ownBytes(hi - lo)
	copy(b, e.raw[lo:hi])
	if cap(dst.pairs) < len(e.pairs) {
		dst.pairs = make([]pair, 0, len(e.pairs))
	}
	dst.pairs = append(dst.pairs[:0], e.pairs...)
	dst.header, dst.version, dst.headerComplete = e.header, e.version, e.headerComplete
	dst.raw = b
	dst.rebase()
	return dst
}

// coveredRange returns the bytes of e.raw that e's header fields and pairs, the first
// pairs of e, cover: from the first header field to the end of the last of pairs, or of
// the last header field Parse reached.
func (e *Event) coveredRange(pairs []pair) (lo, hi int) {
	lo = int(e.header[fieldDeviceVendor].Start)
	if len(pairs) > 0 {
		return lo, int(pairs[len(pairs)-1].end)
	}
	for _, s := range e.header {
		hi = max(hi, int(s.End))
	}
	return lo, hi
}

// keptBytes is the most owned bytes an Event keeps for a copy that needs fewer.
const keptBytes = 64 << 10

// ownBytes returns n bytes of storage e owns, reusing e.owned unless it is too small,
// or holds more than keptBytes for n that does not.
func (e *Event) ownBytes(n int) []byte {
	if c := cap(e.owned); n > c || (c > keptBytes && n <= keptBytes) {
		e.owned = make([]byte, n)
	}
	return e.owned[:n]
}

// rebase moves e's spans down by the start of its Device Vendor field, where the bytes
// e now holds start; a header field Parse did not reach keeps the zero Span.
func (e *Event) rebase() {
	lo := e.header[fieldDeviceVendor].Start
	for i := range e.header {
		if s := &e.header[i]; s.End >= lo {
			s.Start -= lo
			s.End -= lo
		}
	}
	pairs := e.pairs
	for i := range pairs {
		p := &pairs[i]
		p.key -= lo
		p.eq -= lo
		p.end -= lo
	}
}

// cutTrailing reports whether e's last value ends in a space, CR or LF, which only a
// cut at a pair limit leaves: Parse drops them from the end of an extension.
func (e *Event) cutTrailing() bool {
	n := len(e.pairs)
	if n == 0 {
		return false
	}
	last := e.Bytes(e.pairs[n-1].valueSpan())
	return classStart(last, classTrailing) < len(last)
}

// restart makes e an empty event over raw, its storage kept.
func (e *Event) restart(raw []byte) {
	e.raw = raw
	e.header = [headerFields]Span{}
	e.version = 0
	e.pairs = e.pairs[:0]
	e.headerComplete = false
}

// writePairs writes the first shownPairs pairs of e as String shows them.
func (e *Event) writePairs(b *strings.Builder) {
	shown := e.pairs[:min(len(e.pairs), shownPairs)]
	if len(shown) == 0 {
		return
	}
	b.WriteByte('[')
	for i := range shown {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.Write(e.Bytes(shown[i].keySpan()))
		b.WriteByte('=')
		v := e.Bytes(shown[i].valueSpan())
		if cut := v[:min(len(v), shownValueLen)]; hasLineBreak(cut) {
			writeLine(b, cut)
		} else {
			b.Write(cut)
		}
		if len(v) > shownValueLen {
			b.WriteString(summaryCut)
		}
	}
	if len(e.pairs) > len(shown) {
		b.WriteString(summaryMore)
	}
	b.WriteByte(']')
}

// hasLineBreak reports whether b holds a byte up to '\r', as every CR and LF is: a word
// at a time from b's start and from its last scanBytes bytes, or a byte at a time when
// b holds fewer.
func hasLineBreak(b []byte) bool {
	if len(b) < scanBytes {
		return slices.ContainsFunc(b, func(c byte) bool { return c <= '\r' })
	}
	low := lowLanes(binary.LittleEndian.Uint64(b[len(b)-scanBytes:]))
	for p := 0; p+scanBytes < len(b); p += scanBytes {
		low |= lowLanes(binary.LittleEndian.Uint64(b[p:]))
	}
	return low&laneHigh != 0
}

// lowLanes returns a word whose laneHigh bits are not all zero when a byte of w is at
// most '\r'.
func lowLanes(w uint64) uint64 { return (w - ('\r'+1)*laneOnes) &^ w }

// writeLine writes v to b with each CR or LF written as a space.
func writeLine(b *strings.Builder, v []byte) {
	start := 0
	for i, c := range v {
		if c == '\r' || c == '\n' {
			b.Write(v[start:i])
			b.WriteByte(' ')
			start = i + 1
		}
	}
	b.Write(v[start:])
}
