package cef

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Literals the test files share.
const (
	testMsgHelloWorld = "hello world"
	testHeaderOnly    = "CEF:0|Vendor|Product|1.0|100|Name|5|"
)

// warmRuns is how many times assertAllocs runs f before it counts, which
// grows the storage the tested Event keeps.
const warmRuns = 4

// countRuns is how many runs assertAllocs averages.
const countRuns = 100

// raceEnabled reports whether the test binary runs the race detector.
func raceEnabled() bool {
	info, _ := debug.ReadBuildInfo()
	return info != nil && slices.Contains(info.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
}

// assertAllocs fails t unless f allocates want times per run, after a warm-up
// that grows the storage f reuses. The race detector changes allocation counts,
// so under it f runs once, unchecked.
func assertAllocs(t *testing.T, want float64, f func()) {
	t.Helper()
	if raceEnabled() {
		f()
		return
	}
	for range warmRuns {
		f()
	}
	if got := testing.AllocsPerRun(countRuns, f); got != want {
		t.Errorf("allocs per run = %.0f, want %.0f", got, want)
	}
}

// heapCell returns a cell on the heap for a benchmark's results: a call the benchmark
// inlines then allocates what it allocates for a caller that keeps its result.
func heapCell[T any](b *testing.B) *T {
	b.Helper()
	cell := new(T)
	b.Cleanup(func() { _ = *cell })
	return cell
}

// sharedWordAt is the one generic form that could replace wordAt and textWord.
func sharedWordAt[T Text](s T, p int) uint64 {
	tail := min(p, len(s)-scanBytes)
	b := s[tail : tail+scanBytes]
	w := uint64(b[0]) | uint64(b[1])<<lane1 | uint64(b[2])<<lane2 | uint64(b[3])<<lane3 |
		uint64(b[4])<<lane4 | uint64(b[5])<<lane5 | uint64(b[6])<<lane6 | uint64(b[7])<<lane7
	return w >> ((p - tail) * laneBits)
}

// refWord returns the bytes of in from p as a little-endian word, zero past its end.
func refWord(in string, p int) uint64 {
	var w uint64
	for k := range scanBytes {
		if p+k < len(in) {
			w |= uint64(in[p+k]) << (laneBits * k)
		}
	}
	return w
}

// Bounds of assertCost: a linear walk over costScale times the input may cost
// costMargin*costScale times as much, in time and in allocated bytes, far below the
// costScale*costScale of a quadratic walk.
const (
	costScale    = 8
	costMargin   = 3
	costTrials   = 5
	costAttempts = 3
)

// assertCost fails t unless, in one of costAttempts measures, large takes at most
// n = costMargin*scale times as long as small and allocates at most n*(b+1) bytes,
// b being small's; -race only runs both.
func assertCost(t *testing.T, small, large func(), scale int) {
	t.Helper()
	if raceEnabled() {
		small()
		large()
		return
	}
	bound := float64(costMargin * scale)
	var got string
	for range costAttempts {
		smallTime, smallBytes := costOf(small)
		largeTime, largeBytes := costOf(large)
		if largeTime <= time.Duration(bound)*smallTime && float64(largeBytes) <= bound*float64(smallBytes+1) {
			return
		}
		got = fmt.Sprintf("%v and %d bytes, against %v and %d", largeTime, largeBytes, smallTime, smallBytes)
	}
	t.Errorf("the larger run took %s, want at most %g times the smaller", got, bound)
}

// costOf returns the time of the fastest of costTrials runs of f and the bytes
// that run allocated.
func costOf(f func()) (fastest time.Duration, allocated uint64) {
	var before, after runtime.MemStats
	for trial := range costTrials {
		runtime.ReadMemStats(&before)
		start := time.Now()
		f()
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		if trial == 0 || elapsed < fastest {
			fastest, allocated = elapsed, after.TotalAlloc-before.TotalAlloc
		}
	}
	return fastest, allocated
}

// pairsLine returns a valid event of testHeaderOnly's header and n pairs, the i-th
// keyed "key<i>" and valued in turn with an address, a port, words, a timestamp and
// a value with spaces, as firewall events carry them.
func pairsLine(n int) []byte {
	pairValues := [...]string{
		"10.1.2.3", "443", "TCP", "allow", "trust", "web-browsing", "2026-10-27T10:00:00Z",
		"a value with spaces",
	}
	line := []byte(testHeaderOnly)
	for i := range n {
		if i > 0 {
			line = append(line, ' ')
		}
		line = append(line, "key"...)
		line = strconv.AppendInt(line, int64(i), 10)
		line = append(line, '=')
		line = append(line, pairValues[i%len(pairValues)]...)
	}
	return line
}

// corpusLine is one line of a testdata file, named by its file and line number.
type corpusLine struct {
	name string
	line []byte
}

// corpusLines returns every non-empty line of the .cef files under testdata.
func corpusLines(t *testing.T) []corpusLine {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatalf("OpenRoot(testdata) = %v, want nil", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			t.Errorf("Close() of testdata = %v, want nil", closeErr)
		}
	}()
	var lines []corpusLine
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || filepath.Ext(path) != ".cef" {
			return walkErr
		}
		data, readErr := root.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", path, readErr)
		}
		lines = append(lines, fileLines(path, data)...)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(testdata) = %v, want nil", err)
	}
	if len(lines) == 0 {
		t.Fatalf("testdata = %d .cef lines, want the vendor corpus", len(lines))
	}
	return lines
}

// fileLines returns the non-empty lines of data, named by path and line number.
func fileLines(path string, data []byte) []corpusLine {
	var lines []corpusLine
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(line) > 0 {
			lines = append(lines, corpusLine{name: path + ":" + strconv.Itoa(i+1), line: line})
		}
	}
	return lines
}

// refSpan is a byte range [start, end) of the reference parser.
type refSpan struct{ start, end int }

// refPair is one extension pair of the reference parser.
type refPair struct{ key, value refSpan }

// refEvent is what the reference parser reads from an input: the fault's sentinel
// and position, nil and 0 on success, and the event that precedes it.
type refEvent struct {
	err            error
	pos            int
	version        int
	header         [6]refSpan
	pairs          []refPair
	headerComplete bool
}

// refKeyBytes are the bytes a key holds.
const refKeyBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-[]"

// refIsKeyByte reports whether c is one of refKeyBytes.
func refIsKeyByte(c byte) bool { return strings.IndexByte(refKeyBytes, c) >= 0 }

// refIsKey reports whether b is one or more key bytes.
func refIsKey(b []byte) bool {
	for _, c := range b {
		if !refIsKeyByte(c) {
			return false
		}
	}
	return len(b) > 0
}

// refIsVersion reports whether b is 1 to 4 ASCII digits without a leading zero.
func refIsVersion(b []byte) bool {
	if len(b) == 0 || len(b) > 4 || (len(b) > 1 && b[0] == '0') {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// refField returns the end of the header field that starts at i: the first '|' that a
// backslash does not escape, escapes pairing left to right, or len(in).
func refField(in []byte, i int) int {
	for i < len(in) {
		switch in[i] {
		case '\\':
			i += 2
		case '|':
			return i
		default:
			i++
		}
	}
	return len(in)
}

// refBoundary returns the first space at or after from that a run of key bytes and
// an '=' follow, and the position of that '='; -1 and -1 when there is none.
func refBoundary(in []byte, from int) (space, eq int) {
	for p := from; p < len(in); p++ {
		if in[p] != ' ' {
			continue
		}
		q := p + 1
		for q < len(in) && refIsKeyByte(in[q]) {
			q++
		}
		if q > p+1 && q < len(in) && in[q] == '=' {
			return p, q
		}
	}
	return -1, -1
}

// refParse reads in by the grammar Parse documents, written without any function of
// the package: the event, and the fault's sentinel and position.
func refParse(in []byte, maxExtensions int) *refEvent {
	out := new(refEvent)
	switch {
	case len(in) == 0:
		return out.fail(ErrEmpty, 0)
	case int64(len(in)) > 4294967295:
		return out.fail(ErrInputTooLarge, 0)
	case !bytes.HasPrefix(in, []byte("CEF:")):
		return out.fail(ErrPrefix, 0)
	}
	i, ok := out.readVersion(in)
	if !ok {
		return out
	}
	for f := range out.header {
		stop := refField(in, i)
		out.header[f] = refSpan{i, stop}
		if stop == len(in) {
			return out.fail(ErrIncompleteHeader, stop)
		}
		i = stop + 1
	}
	out.headerComplete = true
	return out.extension(in, i, maxExtensions)
}

// fail sets the fault err at pos in out and returns out.
func (out *refEvent) fail(err error, pos int) *refEvent {
	out.err, out.pos = err, pos
	return out
}

// readVersion reads the version token of in into out and returns the position after
// the '|' that ends it, or sets the fault and returns false.
func (out *refEvent) readVersion(in []byte) (int, bool) {
	start := 4
	for start < len(in) && in[start] == ' ' {
		start++
	}
	end := len(in)
	if pipe := bytes.IndexByte(in[start:], '|'); pipe >= 0 {
		end = start + pipe
	}
	if !refIsVersion(in[start:end]) {
		out.fail(ErrVersion, start)
		return 0, false
	}
	for _, c := range in[start:end] {
		out.version = out.version*10 + int(c-'0')
	}
	if end == len(in) {
		out.fail(ErrIncompleteHeader, end)
		return 0, false
	}
	return end + 1, true
}

// refExtension returns the extension of in that starts at i without its trailing
// spaces, CRs and LFs, and the position of its first byte that is not a space.
func refExtension(in []byte, i int) (ext []byte, first int) {
	end := len(in)
	for end > i && strings.IndexByte(" \r\n", in[end-1]) >= 0 {
		end--
	}
	for i < end && in[i] == ' ' {
		i++
	}
	return in[:end], i
}

// extension reads the pairs of in from i into out, at most maxExtensions of them, and
// returns out.
func (out *refEvent) extension(in []byte, i, maxExtensions int) *refEvent {
	ext, i := refExtension(in, i)
	if i == len(ext) {
		return out
	}
	eq := bytes.IndexByte(ext[i:], '=')
	if eq < 0 || !refIsKey(ext[i:i+eq]) {
		return out.fail(ErrExtKey, i)
	}
	var pairs []refPair
	key := refSpan{i, i + eq}
	for {
		valueStart := key.end + 1
		space, next := refBoundary(ext, valueStart)
		if space < 0 {
			pairs = append(pairs, refPair{key, refSpan{valueStart, len(ext)}})
			break
		}
		pairs = append(pairs, refPair{key, refSpan{valueStart, space}})
		key = refSpan{space + 1, next}
	}
	if keep := max(maxExtensions, 0); len(pairs) > keep {
		out.pairs = pairs[:keep]
		return out.fail(ErrExtOverflow, pairs[keep].key.start)
	}
	out.pairs = pairs
	return out
}

// eventDiff returns the first difference between what Parse gave, e and err, and the
// reference event want, or "" when they agree.
func eventDiff(e *Event, err error, want *refEvent) string {
	if diff := faultDiff(err, want); diff != "" {
		return diff
	}
	switch {
	case int(e.Version()) != want.version:
		return fmt.Sprintf("Version() = %d, want %d", e.Version(), want.version)
	case e.HeaderComplete() != want.headerComplete:
		return fmt.Sprintf("HeaderComplete() = %t, want %t", e.HeaderComplete(), want.headerComplete)
	case e.ExtCount() != len(want.pairs):
		return fmt.Sprintf("ExtCount() = %d, want %d", e.ExtCount(), len(want.pairs))
	}
	return spansDiff(e, want)
}

// spansDiff returns the first header field or pair of e whose spans differ from want's,
// or "" when they agree.
func spansDiff(e *Event, want *refEvent) string {
	header := [...]Span{e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(), e.Name(),
		e.Severity()}
	for i, s := range header {
		if w := want.header[i]; !spanIs(s, w) {
			return fmt.Sprintf("header field %d = %v, want [%d:%d]", i, s, w.start, w.end)
		}
	}
	for i, w := range want.pairs {
		if p, ok := e.ExtAt(i); !ok || !spanIs(p.Key, w.key) || !spanIs(p.Value, w.value) {
			return fmt.Sprintf("ExtAt(%d) = %v, %t, want [%d:%d]=[%d:%d]", i, p, ok,
				w.key.start, w.key.end, w.value.start, w.value.end)
		}
	}
	return ""
}

// faultDiff returns the difference between the error Parse gave and the reference
// fault, or "" when they agree.
func faultDiff(err error, want *refEvent) string {
	if want.err == nil {
		if err != nil {
			return fmt.Sprintf("error %v, want nil", err)
		}
		return ""
	}
	if pe := asParseError(err); pe == nil || !errors.Is(err, want.err) || int(pe.Position) != want.pos {
		return fmt.Sprintf("error %v, want %v at byte %d", err, want.err, want.pos)
	}
	return ""
}

// spanIs reports whether s covers the bytes of the reference span w.
func spanIs(s Span, w refSpan) bool { return int(s.Start) == w.start && int(s.End) == w.end }

// asParseError returns the *ParseError err wraps, or nil when it wraps none.
func asParseError(err error) *ParseError {
	var pe *ParseError
	if !errors.As(err, &pe) {
		return nil
	}
	return pe
}
