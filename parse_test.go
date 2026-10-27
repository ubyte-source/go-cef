package cef

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestMaxExtensionsIsTheDocumentedDefault(t *testing.T) {
	if MaxExtensions != 256 {
		t.Fatalf("MaxExtensions = %d, want 256", MaxExtensions)
	}
}

// limitTables are the limits tables of the documents: README's and SECURITY's.
func limitTables() map[string]string {
	return map[string]string{"README.md": "## Operational limits", "SECURITY.md": "## Known Limits"}
}

// limitProbes maps the parameter of each row of the limits tables to the tests that
// pin its value at the bound and one past it.
func limitProbes() map[string][]string {
	return map[string][]string{
		"Pairs per `Parse`": {
			"TestEventParseLimitsThePairs", "TestEventParseExtensionsOverflowKeepsThePairsBefore",
		},
		"`MaxExtensions`": {
			"TestMaxExtensionsIsTheDocumentedDefault", "TestEventParseReadsLargeEvents", "TestEventAppendTextFails",
			"TestEventUnmarshalTextTakesMaxExtensionsPairs",
		},
		"Pair storage": {
			"TestEventGrowPairsDoublesUpToTheLimit", "TestEventGrowPairsFirstTakesTheStartOrALowerLimit",
			"TestEventParseKeepsThePairStorage", "TestEventParseAllocs", "TestEventCloneToSizesThePairsToTheCopy",
		},
		"Input length": {
			"TestExceedsSpansAtTheBound", "TestEventParseReadsAnInputAtTheBound",
			"TestEventParseRefusesAnInputPastTheBound",
		},
		"Version token": {"TestEventParseVersionToken"},
		"Owned bytes of `CloneTo` and `UnmarshalText`": {
			"TestEventCloneToDropsLargeOwnedBytes", "TestEventUnmarshalTextReusesOwnedBytes",
		},
		"Work per input": {
			"TestEventParseCostIsLinear", "TestUnescapeHeaderCostIsLinear", "TestUnescapeExtValueCostIsLinear",
			"TestAppendEscapedHeaderCostIsLinear", "TestAppendEscapedExtValueCostIsLinear",
		},
	}
}

// limitConstants maps each candidate limit constant, the sentinels the rows name
// included, to the parameter of its row, or to "" for one that bounds no input.
func limitConstants() map[string]string {
	return map[string]string{
		"MaxExtensions":     "`MaxExtensions`",
		"versionDigits":     "Version token",
		"keptBytes":         "Owned bytes of `CloneTo` and `UnmarshalText`",
		"pairsStart":        "Pair storage",
		"pairsGrowth":       "Pair storage",
		"ErrExtOverflow":    "Pairs per `Parse`",
		"ErrInputTooLarge":  "Input length",
		"ErrVersion":        "Version token",
		"maxPositionDigits": "",
		"scanBytes":         "",
	}
}

// limitName matches the names that mark a numeric constant as a limit.
var limitName = regexp.MustCompile(`(?i)^(max|min)|limit|(cap|size|bytes|depth)$`)

// tableRows returns the parameter and the text of each row of the table under heading
// in file.
func tableRows(t *testing.T, file, heading string) map[string]string {
	t.Helper()
	text, err := fs.ReadFile(os.DirFS("."), file)
	if err != nil {
		t.Fatalf("read %s: %v, want the document", file, err)
	}
	_, table, found := strings.Cut(string(text), "\n"+heading+"\n")
	if !found {
		t.Fatalf("%s has no %q, want its limits table", file, heading)
	}
	rows := map[string]string{}
	for k, line := range strings.Split(strings.TrimLeft(table, "\n"), "\n") {
		if !strings.HasPrefix(line, "|") {
			break
		}
		if param, _, _ := strings.Cut(strings.TrimPrefix(line, "| "), " | "); k > 1 {
			rows[param] = line
		}
	}
	if len(rows) == 0 {
		t.Fatalf("%s: the table under %q has no row, want the limits", file, heading)
	}
	return rows
}

// packageDecls parses the Go files of the package and returns the functions of its
// tests and, for each constant of its code, whether it holds a number.
func packageDecls(t *testing.T) (tests, consts map[string]bool) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob *.go = %d files, %v, want some", len(files), err)
	}
	tests, consts = map[string]bool{}, map[string]bool{}
	for _, name := range files {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v, want Go", name, err)
		}
		for _, decl := range f.Decls {
			if strings.HasSuffix(name, "_test.go") {
				fileFunc(decl, tests)
			} else {
				fileConsts(decl, consts)
			}
		}
	}
	return tests, consts
}

// fileFunc files the name of a function in funcs.
func fileFunc(decl ast.Decl, funcs map[string]bool) {
	if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
		funcs[fn.Name.Name] = true
	}
}

// fileConsts files in consts each constant of decl, and whether it holds a number; a
// spec without values repeats the values before it.
func fileConsts(decl ast.Decl, consts map[string]bool) {
	gen, ok := decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.CONST {
		return
	}
	var values []ast.Expr
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(vs.Values) > 0 {
			values = vs.Values
		}
		for _, name := range vs.Names {
			consts[name.Name] = !slices.ContainsFunc(values, func(e ast.Expr) bool { return isText(e, consts) })
		}
	}
}

// isText reports whether the constant expression e is a string: a string literal, a
// sum or conversion of one, or a string constant of consts.
func isText(e ast.Expr, consts map[string]bool) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.ParenExpr:
		return isText(v.X, consts)
	case *ast.BinaryExpr:
		return v.Op == token.ADD && (isText(v.X, consts) || isText(v.Y, consts))
	case *ast.CallExpr:
		return callIsText(v, consts)
	case *ast.Ident:
		numeric, declared := consts[v.Name]
		return declared && !numeric
	}
	return false
}

// callIsText reports whether call, a conversion or len, is a string: len of a string
// is a number, a conversion of one is a string.
func callIsText(call *ast.CallExpr, consts map[string]bool) bool {
	if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "len" {
		return false
	}
	return slices.ContainsFunc(call.Args, func(a ast.Expr) bool { return isText(a, consts) })
}

// checkLimitConstants fails t on a constant that a row of rows names, or a numeric
// one whose name marks a limit, without its entry in limitConstants.
func checkLimitConstants(t *testing.T, rows map[string]string, consts map[string]bool) {
	t.Helper()
	known := limitConstants()
	for name, numeric := range consts {
		named := slices.ContainsFunc(slices.Collect(maps.Values(rows)), func(row string) bool {
			return strings.Contains(row, "`"+name+"`")
		})
		if !named && (!numeric || !limitName.MatchString(name)) {
			continue
		}
		switch param, listed := known[name]; {
		case !listed:
			t.Errorf("limitConstants[%s] = absent, want its row, or \"\" for no limit", name)
		case param != "" && rows[param] == "":
			t.Errorf("limitConstants[%s] = %q, want a row of the limits tables", name, param)
		}
	}
	for name := range known {
		if _, declared := consts[name]; !declared {
			t.Errorf("limitConstants lists %s, want a constant of the package", name)
		}
	}
}

// limitRows returns the rows of every limits table, the texts of a parameter's rows
// joined, and fails t unless the tables list the same parameters.
func limitRows(t *testing.T) map[string]string {
	t.Helper()
	rows, params := map[string]string{}, map[string][]string{}
	for file, heading := range limitTables() {
		table := tableRows(t, file, heading)
		for param, line := range table {
			rows[param] += line + "\n"
		}
		params[file] = slices.Sorted(maps.Keys(table))
	}
	if readme, security := params["README.md"], params["SECURITY.md"]; !slices.Equal(readme, security) {
		t.Errorf("limits rows: README %q, SECURITY %q, want the same parameters", readme, security)
	}
	return rows
}

// checkLimitProbes fails t on a row of rows without a probe, and on a probe that is no
// test of tests or belongs to no row.
func checkLimitProbes(t *testing.T, rows map[string]string, tests map[string]bool) {
	t.Helper()
	probes := limitProbes()
	for param := range rows {
		if len(probes[param]) == 0 {
			t.Errorf("the limits row %q has no probe, want the tests that pin it", param)
		}
	}
	for param, names := range probes {
		for _, name := range names {
			if !tests[name] || !strings.HasPrefix(name, "Test") || rows[param] == "" {
				t.Errorf("the probe %s of %q is no test of a row, want both", name, param)
			}
		}
	}
}

func TestMaxExtensionsAndEveryOtherLimitHaveARowAndAProbe(t *testing.T) {
	rows := limitRows(t)
	tests, consts := packageDecls(t)
	checkLimitProbes(t, rows, tests)
	checkLimitConstants(t, rows, consts)
}

func TestEventParseMatchesTheReferenceOnTheCorpus(t *testing.T) {
	var e Event
	for _, c := range corpusLines(t) {
		err := e.Parse(c.line, 256)
		if diff := eventDiff(&e, err, refParse(c.line, 256)); diff != "" {
			t.Errorf("%s: %s\n  input: %q", c.name, diff, c.line)
		}
	}
}

func TestEventParseReadsTheStandardExamples(t *testing.T) {
	testConformance(t, "standard-examples.json")
}

func TestEventParseReadsTheLogstashCases(t *testing.T) {
	testConformance(t, "logstash-cases.json")
}

// conformanceLevel is what SeverityLevel gives for a case: the level's name, the number
// and whether the Severity field is a severity.
type conformanceLevel struct {
	Level  string `json:"level"`
	Number int    `json:"number"`
	OK     bool   `json:"ok"`
}

// conformanceCase is one case of a conformance file of testdata: an input and the
// event, decoded, that Parse reads from it, the fault named by its sentinel.
type conformanceCase struct {
	SeverityLevel *conformanceLevel `json:"severityLevel"`
	Name          string            `json:"name"`
	Line          string            `json:"line"`
	Fault         string            `json:"fault"`
	Header        []string          `json:"header"`
	Pairs         [][]string        `json:"pairs"`
	Version       int               `json:"version"`
}

// testConformance parses the line of each case of the conformance file name and
// compares the decoded event, and its severity level when the case gives one, with
// the case's.
func testConformance(t *testing.T, name string) {
	t.Helper()
	cases := readConformance(t, name)
	var e Event
	for i := range cases {
		c := &cases[i]
		if bad := conformanceShape(c); bad != "" {
			t.Fatalf("%s, case %q: %s", name, c.Name, bad)
		}
		err := e.Parse([]byte(c.Line), MaxExtensions)
		if diff := conformanceDiff(&e, err, c); diff != "" {
			t.Errorf("%s, case %q: %s\n  input: %q", name, c.Name, diff, c.Line)
		}
		if diff := conformanceLevelDiff(&e, c.SeverityLevel); diff != "" {
			t.Errorf("%s, case %q: %s", name, c.Name, diff)
		}
	}
}

// readConformance returns the cases of the conformance file name of testdata, which it
// decodes refusing unknown fields and any input after the array.
func readConformance(t *testing.T, name string) []conformanceCase {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatalf("OpenRoot(testdata) = %v, want nil", err)
	}
	data, err := root.ReadFile(name)
	if closeErr := root.Close(); err != nil || closeErr != nil {
		t.Fatalf("ReadFile(%s), Close() = %v, %v, want nil, nil", name, err, closeErr)
	}
	var cases []conformanceCase
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err, more := dec.Decode(&cases), dec.More(); err != nil || more || len(cases) == 0 {
		t.Fatalf("%s = %d cases, %v, more input %t, want cases, nil and no more input", name, len(cases), err, more)
	}
	return cases
}

// conformanceLevelDiff returns the difference between what SeverityLevel gives for e
// and want, or "" when they agree or the case gives no level.
func conformanceLevelDiff(e *Event, want *conformanceLevel) string {
	if want == nil {
		return ""
	}
	if level, num, ok := e.SeverityLevel(); level.String() != want.Level || num != want.Number || ok != want.OK {
		return fmt.Sprintf("SeverityLevel() = %s, %d, %t, want %s, %d, %t",
			level, num, ok, want.Level, want.Number, want.OK)
	}
	return ""
}

// conformanceShape returns what is malformed in the case c, or "" when it holds six
// header fields and pairs of a key and a value.
func conformanceShape(c *conformanceCase) string {
	if len(c.Header) != 6 {
		return fmt.Sprintf("header = %d fields, want 6", len(c.Header))
	}
	for i, p := range c.Pairs {
		if len(p) != 2 {
			return fmt.Sprintf("pair %d = %d strings, want a key and a value", i, len(p))
		}
	}
	return ""
}

// conformanceFaults maps the fault names of the conformance files to the sentinels,
// and the empty name to no fault.
func conformanceFaults() map[string]error {
	return map[string]error{
		"": nil, "ErrEmpty": ErrEmpty, "ErrPrefix": ErrPrefix, "ErrVersion": ErrVersion,
		"ErrIncompleteHeader": ErrIncompleteHeader, "ErrExtKey": ErrExtKey,
		"ErrExtOverflow": ErrExtOverflow, "ErrInputTooLarge": ErrInputTooLarge,
	}
}

// conformanceDiff returns the first difference between what Parse gave, e and err,
// decoded, and the case want, or "" when they agree.
func conformanceDiff(e *Event, err error, want *conformanceCase) string {
	if sentinel, ok := conformanceFaults()[want.Fault]; !ok || !errors.Is(err, sentinel) {
		return fmt.Sprintf("error %v, want %s", err, want.Fault)
	}
	if got := int(e.Version()); got != want.Version {
		return fmt.Sprintf("Version() = %d, want %d", got, want.Version)
	}
	header := [...]Span{e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(), e.Name(),
		e.Severity()}
	for i, s := range header {
		if got := string(UnescapeHeader(e.Bytes(s), nil)); got != want.Header[i] {
			return fmt.Sprintf("header field %d = %q, want %q", i, got, want.Header[i])
		}
	}
	if e.ExtCount() != len(want.Pairs) {
		return fmt.Sprintf("ExtCount() = %d, want %d", e.ExtCount(), len(want.Pairs))
	}
	for i, w := range want.Pairs {
		p, _ := e.ExtAt(i)
		key, value := e.Text(p.Key), string(UnescapeExtValue(e.Bytes(p.Value), nil))
		if key != w[0] || value != w[1] {
			return fmt.Sprintf("pair %d = %q=%q, want %q=%q", i, key, value, w[0], w[1])
		}
	}
	return ""
}

func TestEventParseVersionToken(t *testing.T) {
	for _, tc := range []struct {
		input   string
		err     error
		pos     uint32
		version Version
	}{
		{"CEF:0|V|P|1|C|N|5|", nil, 0, 0},
		{"CEF:1|V|P|1|C|N|5|", nil, 0, 1},
		{"CEF:   9999|V|P|1|C|N|5|", nil, 0, 9999},
		{"CEF:10000|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:123456789|", ErrVersion, 4, 0},
		{"CEF:01|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:0.1|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:1x|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:0 |V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:1:|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF::|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:  x|", ErrVersion, 6, 0},
		{"CEF:|V|P|1|C|N|5|", ErrVersion, 4, 0},
		{"CEF:", ErrVersion, 4, 0},
		{"CEF:   ", ErrVersion, 7, 0},
		{"CEF:12", ErrIncompleteHeader, 6, 12},
		{"CEF:7|", ErrIncompleteHeader, 6, 7},
	} {
		var e Event
		err := e.Parse([]byte(tc.input), MaxExtensions)
		if tc.err == nil {
			if err != nil {
				t.Errorf("Parse(%q) = %v, want nil", tc.input, err)
			}
		} else if pe := asParseError(err); pe == nil || !errors.Is(err, tc.err) || pe.Position != tc.pos {
			t.Errorf("Parse(%q) = %v, want %v at byte %d", tc.input, err, tc.err, tc.pos)
		}
		if e.Version() != tc.version {
			t.Errorf("Parse(%q): Version() = %d, want %d", tc.input, e.Version(), tc.version)
		}
	}
}

func TestEventParseNeedsTheSeventhPipe(t *testing.T) {
	input := []byte("CEF:0|V|P|1|C|N|5 src=1.2.3.4")
	var e Event
	err := e.Parse(input, MaxExtensions)
	if pe := asParseError(err); pe == nil || !errors.Is(err, ErrIncompleteHeader) ||
		int(pe.Position) != len(input) {
		t.Fatalf("Parse(%q) = %v, want ErrIncompleteHeader at byte %d", input, err, len(input))
	}
	if e.HeaderComplete() {
		t.Errorf("Parse(%q): HeaderComplete() = true, want false", input)
	}
	if got := e.Text(e.Name()); got != "N" {
		t.Errorf("Parse(%q): Name() = %q, want %q", input, got, "N")
	}
	if got := e.Text(e.Severity()); got != "5 src=1.2.3.4" {
		t.Errorf("Parse(%q): Severity() = %q, want the rest of the input", input, got)
	}
}

func TestEventParseHeaderEscapes(t *testing.T) {
	for _, tc := range []struct {
		input string
		name  string
		sev   string
	}{
		{`CEF:0|V|P|1|C|a\|b|5|`, `a\|b`, "5"},
		{`CEF:0|V|P|1|C|a\\|5|`, `a\\`, "5"},
		{`CEF:0|V|P|1|C|a\\\|b|5|`, `a\\\|b`, "5"},
		{`CEF:0|V|P|1|C|\|\|\||5|`, `\|\|\|`, "5"},
		{`CEF:0|V|P|1|C|x=y\n|5|`, `x=y\n`, "5"},
	} {
		var e Event
		if err := e.Parse([]byte(tc.input), MaxExtensions); err != nil {
			t.Fatalf("Parse(%q) = %v, want nil", tc.input, err)
		}
		if got := e.Text(e.Name()); got != tc.name {
			t.Errorf("Parse(%q): Name() = %q, want %q", tc.input, got, tc.name)
		}
		if got := e.Text(e.Severity()); got != tc.sev {
			t.Errorf("Parse(%q): Severity() = %q, want %q", tc.input, got, tc.sev)
		}
	}
}

func TestEventParseHeaderEndsInAnEscape(t *testing.T) {
	for _, name := range []string{`N\|`, `N\|\`, `N\|\\`, `N\|\|`, `N\|\\\`} {
		input := []byte("CEF:0|V|P|1|C|" + name)
		var e Event
		err := e.Parse(input, MaxExtensions)
		if pe := asParseError(err); pe == nil || !errors.Is(err, ErrIncompleteHeader) ||
			int(pe.Position) != len(input) {
			t.Errorf("Parse(%q) = %v, want ErrIncompleteHeader at byte %d", input, err, len(input))
		}
		if got := e.Text(e.Name()); got != name {
			t.Errorf("Parse(%q): Name() = %q, want %q", input, got, name)
		}
	}
}

// headerBodies returns every text of up to 8 bytes over 'a', '|' and '\', and texts
// of 9 to 17 bytes with one '|', 'a' or `\|` among 'a' or '|' at each place.
func headerBodies() []string {
	bodies, level := []string{""}, []string{""}
	for range 8 {
		next := make([]string, 0, 3*len(level))
		for _, s := range level {
			next = append(next, s+"a", s+"|", s+`\`)
		}
		bodies, level = append(bodies, next...), next
	}
	for n := 9; n <= 17; n++ {
		for k := range n {
			for _, tc := range [...]struct{ fill, at string }{{"a", "|"}, {"|", "a"}, {"a", `\|`}, {"|", `\|`}} {
				b := []byte(strings.Repeat(tc.fill, n))
				copy(b[k:], tc.at)
				bodies = append(bodies, string(b))
			}
		}
	}
	return bodies
}

func TestEventParseMatchesTheReferenceAtEachLane(t *testing.T) {
	for _, prefix := range []string{"CEF:0|", "CEF:10|", "CEF:100|", "CEF: 1000|"} {
		for _, body := range headerBodies() {
			input := []byte(prefix + body)
			var e Event
			err := e.Parse(input, MaxExtensions)
			if diff := eventDiff(&e, err, refParse(input, MaxExtensions)); diff != "" {
				t.Fatalf("Parse(%q): %s", input, diff)
			}
		}
	}
}

func TestEventParseFaultsAtThePrefix(t *testing.T) {
	for _, tc := range []struct {
		input string
		err   error
	}{
		{"", ErrEmpty},
		{"C", ErrPrefix},
		{"cef:0|V|P|1|C|N|5|", ErrPrefix},
		{"<134>CEF:0|V|P|1|C|N|5|", ErrPrefix},
		{testMsgHelloWorld, ErrPrefix},
	} {
		var e Event
		err := e.Parse([]byte(tc.input), MaxExtensions)
		if pe := asParseError(err); pe == nil || !errors.Is(err, tc.err) || pe.Position != 0 {
			t.Errorf("Parse(%q) = %v, want %v at byte 0", tc.input, err, tc.err)
		}
		if e.HeaderComplete() || e.Version() != 0 || e.ExtCount() != 0 {
			t.Errorf("Parse(%q): HeaderComplete %t, Version %d, ExtCount %d, want the zero event",
				tc.input, e.HeaderComplete(), e.Version(), e.ExtCount())
		}
	}
}

func TestEventParseLimitsThePairs(t *testing.T) {
	input := []byte(testHeaderOnly + "a=1 b=2 c=3")
	first := len(testHeaderOnly)
	for _, tc := range []struct {
		limit int
		pairs int
		pos   int
	}{
		{-1, 0, first},
		{0, 0, first},
		{1, 1, first + len("a=1 ")},
		{2, 2, first + len("a=1 b=2 ")},
		{3, 3, -1},
		{256, 3, -1},
	} {
		var e Event
		err := e.Parse(input, tc.limit)
		if tc.pos < 0 {
			if err != nil {
				t.Errorf("Parse(%q, %d) = %v, want nil", input, tc.limit, err)
			}
		} else if pe := asParseError(err); pe == nil || !errors.Is(err, ErrExtOverflow) ||
			int(pe.Position) != tc.pos {
			t.Errorf("Parse(%q, %d) = %v, want ErrExtOverflow at byte %d", input, tc.limit, err, tc.pos)
		}
		if e.ExtCount() != tc.pairs || !e.HeaderComplete() {
			t.Errorf("Parse(%q, %d): ExtCount() = %d, HeaderComplete() = %t, want %d and true",
				input, tc.limit, e.ExtCount(), e.HeaderComplete(), tc.pairs)
		}
	}
}

func TestEventParseReadsLargeEvents(t *testing.T) {
	for _, n := range []int{58, 106, 171, 256} {
		line := pairsLine(n)
		var e Event
		err := e.Parse(line, MaxExtensions)
		if diff := eventDiff(&e, err, refParse(line, 256)); diff != "" || e.ExtCount() != n {
			t.Errorf("Parse(pairsLine(%d)): %s, ExtCount() = %d, want %d pairs", n, diff, e.ExtCount(), n)
		}
	}
	line := pairsLine(257)
	var e Event
	err := e.Parse(line, MaxExtensions)
	if diff := eventDiff(&e, err, refParse(line, 256)); diff != "" || !errors.Is(err, ErrExtOverflow) {
		t.Errorf("Parse(pairsLine(257)) = %v, %s, want ErrExtOverflow with 256 pairs", err, diff)
	}
}

func TestEventParseKeepsThePairStorage(t *testing.T) {
	var e Event
	line := pairsLine(171)
	if err := e.Parse(line, MaxExtensions); err != nil {
		t.Fatalf("Parse(pairsLine(171)) = %v, want nil", err)
	}
	if got := cap(e.pairs); got > 256 {
		t.Errorf("pair storage = %d pairs, want at most the limit 256", got)
	}
	storage, first := cap(e.pairs), &e.pairs[0]
	if err := e.Parse(line, 200); err != nil {
		t.Fatalf("Parse(pairsLine(171), 200) = %v, want nil", err)
	}
	if cap(e.pairs) != storage || &e.pairs[0] != first {
		t.Errorf("a second Parse moved the pair storage: %d pairs, want the %d kept", cap(e.pairs), storage)
	}
	var fresh Event
	if err := fresh.Parse(line, 171); err != nil || cap(fresh.pairs) != 171 {
		t.Errorf("Parse(pairsLine(171), 171) = %v, storage %d pairs, want nil and 171", err, cap(fresh.pairs))
	}
}

func TestExceedsSpansAtTheBound(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("an int of 32 bits cannot hold the bound")
	}
	bound := uint64(4294967295)
	if exceedsSpans(int(bound)) {
		t.Errorf("exceedsSpans(%d) = true, want false", bound)
	}
	if !exceedsSpans(int(bound + 1)) {
		t.Errorf("exceedsSpans(%d) = false, want true", bound+1)
	}
	if got := exceedsSpans(0); got {
		t.Errorf("exceedsSpans(0) = %t, want false", got)
	}
}

// mappedZeros returns size mapped zero bytes, unmapped when t ends, or skips t where
// an int or the system cannot hold them.
func mappedZeros(t *testing.T, size uint64) []byte {
	t.Helper()
	if size > math.MaxInt {
		t.Skipf("an int of %d bits cannot hold %d bytes", strconv.IntSize, size)
		return nil
	}
	input, err := syscall.Mmap(-1, 0, int(size), syscall.PROT_READ,
		syscall.MAP_ANON|syscall.MAP_PRIVATE|syscall.MAP_NORESERVE)
	if err != nil {
		t.Skipf("mapping %d bytes: %v", size, err)
	}
	t.Cleanup(func() {
		if unmapErr := syscall.Munmap(input); unmapErr != nil {
			t.Errorf("Munmap(input) = %v, want nil", unmapErr)
		}
	})
	return input
}

func TestEventParseReadsAnInputAtTheBound(t *testing.T) {
	input := mappedZeros(t, math.MaxUint32)
	var e Event
	err := e.Parse(input, MaxExtensions)
	if pe := asParseError(err); pe == nil || !errors.Is(err, ErrPrefix) || pe.Position != 0 {
		t.Errorf("Parse(%d zero bytes) = %v, want ErrPrefix at byte 0", len(input), err)
	}
}

func TestEventParseRefusesAnInputPastTheBound(t *testing.T) {
	input := mappedZeros(t, math.MaxUint32+1)
	var e Event
	err := e.Parse(input, MaxExtensions)
	if pe := asParseError(err); pe == nil || !errors.Is(err, ErrInputTooLarge) || pe.Position != 0 {
		t.Errorf("Parse(%d bytes) = %v, want ErrInputTooLarge at byte 0", len(input), err)
	}
	if e.raw != nil {
		t.Errorf("Parse(%d bytes) keeps %d input bytes, want none, the zero event", len(input), len(e.raw))
	}
	var u Event
	err = u.UnmarshalText(input)
	if pe := asParseError(err); pe == nil || !errors.Is(err, ErrInputTooLarge) || pe.Position != 0 {
		t.Errorf("UnmarshalText(%d bytes) = %v, want ErrInputTooLarge at byte 0", len(input), err)
	}
	if got := cap(u.owned); got != 0 || u.raw != nil {
		t.Errorf("UnmarshalText(%d bytes) = %d owned bytes and %d input bytes, want none, the zero event",
			len(input), got, len(u.raw))
	}
}

func TestEventParseAllocs(t *testing.T) {
	line := pairsLine(58)
	var warm Event
	var err error
	assertAllocs(t, 0, func() { err = warm.Parse(line, MaxExtensions) })
	if err != nil {
		t.Errorf("Parse(pairsLine(58)) = %v, want nil", err)
	}
	bad := []byte("CEF:0|V|P")
	assertAllocs(t, 1, func() { err = warm.Parse(bad, MaxExtensions) })
	if !errors.Is(err, ErrIncompleteHeader) {
		t.Errorf("Parse(%q) = %v, want ErrIncompleteHeader", bad, err)
	}
	large := pairsLine(171)
	assertAllocs(t, 5, func() {
		var e Event
		err = e.Parse(large, MaxExtensions)
	})
	if err != nil {
		t.Errorf("Parse(pairsLine(171)) into a fresh Event = %v, want nil", err)
	}
}

func TestEventParseCostIsLinear(t *testing.T) {
	shapes := map[string]func(n int) []byte{
		"equals runs": func(n int) []byte {
			return []byte(testHeaderOnly + "k=" + strings.Repeat("ab=", n))
		},
		"long keys": func(n int) []byte {
			return []byte(testHeaderOnly + "k=v " + strings.Repeat("a", n) + "=x")
		},
		"one key": func(n int) []byte { return []byte(testHeaderOnly + strings.Repeat("k", n) + "=v") },
		"short pairs": func(n int) []byte {
			return []byte(testHeaderOnly + "k=v" + strings.Repeat(" a=", n))
		},
		"invalid keys": func(n int) []byte {
			return []byte(testHeaderOnly + "k=" + strings.Repeat(" a:b=", n))
		},
		"escaped value": func(n int) []byte {
			return []byte(testHeaderOnly + "k=" + strings.Repeat(`\=\\`, n))
		},
		"escaped pipes": func(n int) []byte {
			return []byte("CEF:0|V|P|1|C|" + strings.Repeat(`\|`, n) + "|5|")
		},
		"backslash runs": func(n int) []byte {
			return []byte("CEF:0|V|P|1|C|" + strings.Repeat(`\\\\\\\|`, n) + "|5|")
		},
	}
	for name, shape := range shapes {
		small, large := shape(4096), shape(4096*costScale)
		var e Event
		var err error
		assertCost(t, func() { err = e.Parse(small, 1<<30) }, func() { err = e.Parse(large, 1<<30) }, costScale)
		if err != nil || t.Failed() {
			t.Fatalf("shape %s: Parse = %v, failed %t, want nil and a linear cost", name, err, t.Failed())
		}
	}
}

func FuzzEventParse(f *testing.F) {
	for _, seed := range []string{
		testHeaderOnly, testHeaderOnly + "src=10.0.0.1 dst=2.2.2.2 msg=a b\\=c",
		`CEF:0|V|P|1|C|a\|b|5|k=v\=w`, "CEF:01|", "CEF:1x|", "CEF:0|V|P|1|C|N|5",
		testHeaderOnly + "junk", testHeaderOnly + "a=1 bad key=2\r\n", testHeaderOnly + "  ",
	} {
		f.Add([]byte(seed), 3)
	}
	f.Fuzz(func(t *testing.T, input []byte, limit int) {
		limit %= 300
		var e Event
		err := e.Parse(input, limit)
		if diff := eventDiff(&e, err, refParse(input, limit)); diff != "" {
			t.Fatalf("Parse(%q, %d): %s", input, limit, diff)
		}
	})
}

// conformingLine builds an event of the given header fields and pairs, each escaped by
// hand.
func conformingLine(header, keys, values []string) []byte {
	line := []byte("CEF:0")
	for _, f := range header {
		line = append(line, '|')
		for i := range len(f) {
			switch c := f[i]; c {
			case '\\', '|':
				line = append(line, '\\', c)
			case '\r', '\n':
				line = append(line, ' ')
			default:
				line = append(line, c)
			}
		}
	}
	line = append(line, '|')
	for i, k := range keys {
		if i > 0 {
			line = append(line, ' ')
		}
		line = append(line, k...)
		line = append(line, '=')
		line = append(line, strings.NewReplacer(`\`, `\\`, "=", `\=`, "\r", `\r`, "\n", `\n`).Replace(values[i])...)
	}
	return line
}

func FuzzEventParseConforming(f *testing.F) {
	f.Add("Vendor", "Product", "1.0", "100", "a | b", "5", "src", "10.0.0.1", "msg", "x = y \\ z")
	f.Fuzz(func(t *testing.T, vendor, product, version, class, name, sev, k1, v1, k2, v2 string) {
		header := []string{vendor, product, version, class, name, sev}
		if !refIsKey([]byte(k1)) || !refIsKey([]byte(k2)) {
			return
		}
		v2 = strings.TrimRight(v2, " ")
		line := conformingLine(header, []string{k1, k2}, []string{v1, v2})
		var e Event
		if err := e.Parse(line, MaxExtensions); err != nil {
			t.Fatalf("Parse(%q) = %v, want nil", line, err)
		}
		spans := [...]Span{e.DeviceVendor(), e.DeviceProduct(), e.DeviceVersion(), e.DeviceEventClassID(), e.Name(),
			e.Severity()}
		for i, s := range spans {
			want := strings.NewReplacer("\r", " ", "\n", " ").Replace(header[i])
			if got := string(UnescapeHeader(e.Bytes(s), nil)); got != want {
				t.Fatalf("Parse(%q): header field %d = %q, want %q", line, i, got, want)
			}
		}
		for i, want := range [][2]string{{k1, v1}, {k2, v2}} {
			p, ok := e.ExtAt(i)
			if !ok || e.Text(p.Key) != want[0] || string(UnescapeExtValue(e.Bytes(p.Value), nil)) != want[1] {
				t.Fatalf("Parse(%q): pair %d = %q=%q, want %q=%q", line, i, e.Bytes(p.Key),
					UnescapeExtValue(e.Bytes(p.Value), nil), want[0], want[1])
			}
		}
	})
}

// parseShapes are the inputs of BenchmarkEventParse: vendor events, escapes and the
// adversarial shapes of the cost test.
func parseShapes() []struct {
	name  string
	input []byte
} {
	return []struct {
		name  string
		input []byte
	}{
		{"Minimal", []byte("CEF:0|Cisco|CyberVision|4.0|100|Alert|5|")},
		{"HeaderOnly", []byte(testHeaderOnly)},
		{"CiscoASA", []byte("CEF:0|Cisco|ASA|9.16|430003|ACL deny|7|src=192.168.1.1 dst=10.0.0.1 " +
			"spt=12345 dpt=443 proto=TCP act=Deny cs1=outside cs1Label=Interface msg=Denied TCP connection")},
		{"PaloAlto", []byte("CEF:0|Palo Alto Networks|PAN-OS|11.0|TRAFFIC|end|3|src=10.0.0.1 " +
			"dst=172.16.0.1 spt=45678 dpt=80 proto=TCP act=allow PanOSRuleUUID=abc-123 " +
			"PanOSSourceZone=trust PanOSDestinationZone=untrust")},
		{"Escaped", []byte(`CEF:0|security|threatmanager|1.0|100|detected a \| in message|10|` +
			`src=10.0.0.1 msg=test\=value\nwith escapes act=blocked a | dst=1.1.1.1`)},
		{"Pairs58", pairsLine(58)},
		{"Pairs106", pairsLine(106)},
		{"Pairs171", pairsLine(171)},
		{"EqualsRun", []byte(testHeaderOnly + "k=" + strings.Repeat("ab=", 1000))},
		{"EscapedPipes", []byte("CEF:0|V|P|1|C|" + strings.Repeat(`\|`, 1000) + "|5|")},
	}
}

func BenchmarkEventParse(b *testing.B) {
	for _, s := range parseShapes() {
		b.Run(s.name, func(b *testing.B) {
			var e Event
			err := e.Parse(s.input, MaxExtensions)
			if diff := eventDiff(&e, err, refParse(s.input, MaxExtensions)); err != nil || diff != "" {
				b.Fatalf("Parse(%q) = %v, %s, want nil and refParse's event", s.input, err, diff)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(s.input)))
			for b.Loop() {
				if err := e.Parse(s.input, MaxExtensions); err != nil {
					b.Fatalf("Parse(%s) = %v, want nil", s.name, err)
				}
			}
		})
	}
}

func BenchmarkWordAt(b *testing.B) {
	input := []byte(strings.Repeat("CEF:0|Palo Alto Networks|PAN-OS|11.0|", 2))
	for p := 0; p < len(input); p += scanBytes {
		want := refWord(string(input), p)
		if got, shared := wordAt(input, p), sharedWordAt(input, p); got != want || shared != want {
			b.Fatalf("wordAt, sharedWordAt(input, %d) = %#x, %#x, want %#x", p, got, shared, want)
		}
	}
	b.Run("Own", func(b *testing.B) {
		out := heapCell[uint64](b)
		b.ReportAllocs()
		b.SetBytes(int64(len(input)))
		for b.Loop() {
			var m uint64
			for p := 0; p < len(input); p += scanBytes {
				m += pipeLanes(wordAt(input, p))
			}
			*out = m
		}
	})
	b.Run("SharedForm", func(b *testing.B) {
		out := heapCell[uint64](b)
		b.ReportAllocs()
		b.SetBytes(int64(len(input)))
		for b.Loop() {
			var m uint64
			for p := 0; p < len(input); p += scanBytes {
				m += pipeLanes(sharedWordAt(input, p))
			}
			*out = m
		}
	})
}

func ExampleEvent_Parse() {
	line := []byte(`CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|` +
		`src=10.0.0.1 dst=2.1.2.2 spt=1232`)
	var e Event
	if err := e.Parse(line, MaxExtensions); err != nil {
		fmt.Println(err)
		return
	}
	src, _ := e.ExtString("src")
	fmt.Println(e.Text(e.DeviceVendor()), e.Text(e.Name()), e.Text(src))
	// Output: Security worm successfully stopped 10.0.0.1
}

func ExampleEvent_Parse_syslog() {
	packet := []byte(`<134>Oct 27 10:00:00 fw1 CEF:0|Vendor|Product|1.0|100|Name|5|act=allow`)
	start := max(bytes.Index(packet, []byte("CEF:")), 0)
	var e Event
	err := e.Parse(packet[start:], MaxExtensions)
	act, _ := e.ExtString("act")
	fmt.Println(err, e.Text(act))
	// Output: <nil> allow
}
