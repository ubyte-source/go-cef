# Contributing

## Prerequisites

- Go 1.25 or later, the version in `go.mod`; CI tests on Go 1.25.14 and Go 1.27.3. The race detector
  needs cgo.
- make, and jq for `make testtime`.

The Makefile runs every tool at a pinned version through `go run`: golangci-lint v2.14.0,
govulncheck v1.8.0, deadcode v0.50.0 and nilaway v0.0.0-20260918162853-acb8859b9031. Nothing needs a
global install; `GOLANGCI_LINT=<path>`, `GOVULNCHECK=<path>`, `DEADCODE=<path>` and `NILAWAY=<path>`
point the targets at local binaries of the same versions. golangci-lint builds and runs with Go
1.27.3 (`GOTOOLCHAIN=go1.27.3`), and so does the fuzzer of `make fuzz`; deadcode needs Go 1.26 or
later, so `lint.yml` runs it on Go 1.27.3. The go command fetches a missing toolchain.

```bash
git clone https://github.com/ubyte-source/go-cef.git
cd go-cef
make ci
```

## Workflow

1. Branch from `main`.
2. Change the code together with its tests and with every document the change makes untrue: README
   (behaviour, benchmarks and limits) and SECURITY (defenses and limits).
3. Run `make ci` until it passes.
4. Open a pull request describing what changes, why, and how it was tested.

`make ci` runs these targets, and the workflows run the same ones: `lint.yml` runs `lint` and
`deadcode` on Go 1.27.3, `test.yml` runs `modcheck`, `vet`, `test`, `test386`, `cover` and
`bench-smoke` on Go 1.25.14 and 1.27.3, and `security.yml` runs `vuln` next to CodeQL.

| Target        | Gate |
|---------------|------|
| `modcheck`    | `go mod download`, `go mod verify` and `go mod tidy -diff` |
| `vet`         | `go vet ./...` |
| `lint`        | golangci-lint v2.14.0 with `.golangci.yml`, test files included (gosec runs inside it) |
| `vuln`        | govulncheck v1.8.0 on the module and the toolchain |
| `deadcode`    | deadcode v0.50.0 `-test ./...`; any output fails |
| `test`        | the tests with `-shuffle=on`; this run and `test386` check the allocation counts, which the race detector changes |
| `test386`     | the tests with `GOARCH=386`, so 32-bit arithmetic is gated |
| `race`        | the tests with `-race`, `-shuffle=on` and `CGO_ENABLED=1`, writing `coverage.out` |
| `bench-smoke` | every benchmark 100 times, `-benchtime=100x` |
| `cover`       | `race`, then `coverage.html` and the total; fails on any statement the tests leave uncovered |

`make testtime` runs the tests one at a time under the race detector and fails on any test slower
than `TESTTIME_MAX` seconds (10). `make final` runs the delivery gates one after another on an idle
machine: `fmtcheck` (`gofmt -s`), `nilaway`, `race-repeat` (`-race -count=10 -shuffle=on`),
`fuzz-final` (every fuzz target for 60 s) and `treecheck`, which after `make clean` fails on an
artefact, an untracked file of no source kind, a file under `testdata/fuzz` (a crasher is an
`f.Add` seed of its target), an empty directory, a file not stored with LF, or a `.gitattributes`
without `* text=auto eol=lf`.

`make help` lists every target. The fuzz workflow runs every fuzz target weekly, reading the list
through `make fuzz-list`, which asks `go test -list '^Fuzz'` for every `Fuzz` function of the module
and fails when there is none. `make fuzz` runs the same list for `FUZZTIME` each, or only the
`pkg:Target` entries of `FUZZ_TARGETS`, and fails on an entry that names no fuzz target.

## Code

- Control flow stays linear; one helper per concern, no duplicated logic, no dead code, no code that
  exists only for tests, and no mutable package state.
- Every export allocates only where its godoc says so, and its test asserts the exact count.
- A type is declared above its first use in the file.
- Struct fields are grouped by meaning, with the boolean flags in one trailing block; govet runs
  every analyzer but `fieldalignment`.
- No file imports `unsafe`, tests included, and the module has no dependency.
- `//nolint` names one linter and says why the code is safe.

## Comments

- English, present tense, short: at most 3 lines per block and 88 columns.
- They explain what the code cannot say: no history, no notes to self, no citation of a standard, an
  RFC or a Markdown file, no restated code and no commented-out code.
- The godoc of every exported identifier is a complete sentence that starts with its name.
- One package comment, in `doc.go`, one paragraph, which may be longer.

## Tests

- Every code file `foo.go` has exactly one sibling `foo_test.go` holding all its tests, benchmarks,
  fuzz targets and examples. `doc.go` has none, and `doc_test.go` holds only the fixtures that two
  or more test files use, the reference parser among them, never tests.
- Test names start with a symbol declared in the sibling file: `Test<Symbol><Scenario>` in
  CamelCase, such as `TestEventParseNeedsTheSeventhPipe`.
- Assertions use the standard library only (`t.Fatalf` and `t.Errorf` with got and want). A negative
  test asserts the specific sentinel, and the byte offset of a `ParseError`.
- Every export has an exact allocation check through `assertAllocs`, which skips the count under the
  race detector.
- Every export has a benchmark that fails when its result is wrong, checked once before the timed
  loop, times with `b.Loop()` and reports allocations.
- Every export is called by a fuzz target whose oracle is written independently of the code: the
  reference parser of `doc_test.go`, the tables of Version 27 written as literals, `strconv`, `utf8`
  or a reference unescaper.
- A shape that could cost more than linear time is timed at two sizes with `assertCost`.
- Statement coverage stays at 100%, and the tests pass with `GOARCH=386` too.
- The tests build on unix only: two map 4294967295 and 4294967296 bytes with `syscall.Mmap`, the
  input bound and one byte past it, without touching memory.
- Each go block of README is a run of lines of an Example, which `go test` runs against its Output
  comment.
- A test must fail when the behavior it names breaks; check it by breaking the code once before you
  trust it.

An event file under `testdata` holds one event per line in a `.cef` file, and
`TestEventParseMatchesTheReferenceOnTheCorpus` checks every line of every such file against the
reference parser.

## Benchmarks

Compare a change with `benchstat` on an idle machine, the benchmarks pinned to the same cores:

```bash
go test -run '^$' -bench . -benchmem -count 10 > old.txt
# apply the change
go test -run '^$' -bench . -benchmem -count 10 > new.txt
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20260610192853-712aea8b4705 old.txt new.txt
```

A change made for speed lands when benchstat shows a significant gain on its target and no
significant regression on any other benchmark. README's benchmark table comes from the medians of
ten runs of every benchmark and names its command and host.

## Releases

`main` is the only long-lived branch: every change reaches it from a short branch whose CI passes. A
release is a tag `vMAJOR.MINOR.PATCH` on a commit of `main`, by SemVer; SECURITY lists the supported
versions.

## Commit messages

Imperative mood, a subject of at most 50 characters, a blank line, then what changes and why.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 of the
project.
