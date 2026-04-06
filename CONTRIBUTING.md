# Contributing to go-cef

## Development Prerequisites

- **Go 1.25+**
- Make

## Getting Started

```bash
git clone https://github.com/ubyte-source/go-cef.git
cd go-cef
make all
```

## Running Tests

```bash
make test        # All tests with race detector
make bench       # Benchmarks with memory profiling
make fuzz        # Native Go fuzzing (30s)
make cover       # Coverage report
make vet         # Static analysis
```

## Zero-Allocation Constraint

The hot path (`Parse`, `Ext`, `ExtString`, `Bytes`, `SeverityNum`) must produce
**0 allocations per operation**. This is enforced by benchmarks with `-benchmem`.

All benchmarks must use `b.Loop()` (Go 1.25+), not `for i := 0; i < b.N; i++`.

Before submitting a change, run:
```bash
go test -bench=. -benchmem ./...
```

Every benchmark line must show `0 B/op` and `0 allocs/op`.

## Adding Vendor Test Data

1. Create a directory under `testdata/<vendor>/`
2. Add `.cef` files with one CEF message per line
3. The data-driven test in `parse_testdata_test.go` will automatically pick them up
4. Run `make test` to verify

## Code Style

- Follow standard Go conventions (`gofmt`, `goimports`)
- Run `golangci-lint run ./...` if available (see `.golangci.yml`)
- Comments in English, no abbreviations
- Every exported function and type must have a godoc comment

## Architecture

```
cef.go         — Types: Parser, Event, ParserOption, Span, ExtPair, Clone, Marshal
parse.go       — Parse, ParseString, parseVersion, parseHeaderFields, scanField
extensions.go  — Extension key=value parsing: parseExtensions, findValueEnd
unescape.go    — Unescape helpers for header and extension values
errors.go      — Error types with positional information, makeError
severity.go    — SeverityNum(), SeverityLevel() — on-demand conversion
doc.go         — Package documentation
```

## Design Principles

1. **One type, one job.** No helpers, no utilities — just types with clear responsibilities.
2. **Zero-alloc is a constraint, not a goal.** It guides every design decision.
3. **The parser eats everything.** Permissive by default, errors are informative.
4. **Errors as values.** Every error includes position and reason.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
