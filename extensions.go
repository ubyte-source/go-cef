package cef

import "bytes"

// Growth of the pair storage in Parse: each growth multiplies the storage by
// pairsGrowth, to pairsStart at least and to the Parse limit at most.
const (
	pairsStart  = 16
	pairsGrowth = 2
)

// parseExtensions reads at most limit pairs from the extension that starts at p, its
// trailing spaces, CRs and LFs dropped: each value ends at the space before the first
// run of key bytes that a space precedes and an '=' ends.
func (e *Event) parseExtensions(p, limit int) error {
	ext := e.raw[:p+classStart(e.raw[p:], classTrailing)]
	p = skipSpaces(ext, p)
	if p == len(ext) {
		return nil
	}
	i := bytes.IndexByte(ext[p:], '=')
	if i < 0 || !ValidKey(ext[p:p+i]) {
		return fault(p, ErrExtKey)
	}
	key, eq := p, p+i
	for {
		if len(e.pairs) >= limit {
			return fault(key, ErrExtOverflow)
		}
		end, next := valueEnd(ext, eq+1)
		if len(e.pairs) == cap(e.pairs) {
			e.growPairs(limit)
		}
		e.pairs = append(e.pairs, pair{
			key: offset(key), eq: offset(eq), end: offset(end), pack: keyPack(ext[key:eq]),
		})
		if next < 0 {
			return nil
		}
		key, eq = end+1, next
	}
}

// classStart returns the start of the run of bytes of class that ends b.
func classStart(b []byte, class byte) int {
	n := len(b)
	for n > 0 && byteClasses[b[n-1]]&class != 0 {
		n--
	}
	return n
}

// valueEnd returns the end of the value that starts at p, the space before the next
// key, and next, that key's '='; next is -1 when no key follows. A key run stops at the
// '=' before it at the latest, so each byte is read for one '=' only.
func valueEnd(ext []byte, p int) (end, next int) {
	for {
		i := bytes.IndexByte(ext[p:], '=')
		if i < 0 {
			return len(ext), -1
		}
		before := ext[:p+i]
		if k := classStart(before, classKey); k > 0 && k < len(before) && before[k-1] == ' ' {
			return k - 1, len(before)
		}
		p += i + 1
	}
}

// growPairs grows the pair storage by pairsGrowth, to pairsStart at least and to limit
// at most.
func (e *Event) growPairs(limit int) {
	grown := make([]pair, len(e.pairs), min(max(pairsGrowth*cap(e.pairs), pairsStart), limit))
	copy(grown, e.pairs)
	e.pairs = grown
}
