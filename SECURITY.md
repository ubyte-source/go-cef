# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in go-cef, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Use GitHub's private vulnerability reporting feature, or email the maintainers directly.
3. Include: description, steps to reproduce, and impact assessment.
4. We will acknowledge receipt within 48 hours and provide a fix timeline.

## Threat Model

go-cef reads events that callers take from untrusted senders, syslog from the network above all: the
bytes `Parse`, `UnmarshalText`, `UnescapeHeader` and `UnescapeExtValue` read. It defends against:

- Resource exhaustion: time or memory that grows faster than the input, and pair storage past the
  limit the caller declares.
- Panics on any input.
- Readings that shift fields: an extension read as the Severity field, a header field cut at an
  escaped `|`, a pair split where no key starts.
- Views that let an append write over the input.
- Input bytes reaching a caller's logs through errors.

## Implemented Defenses

- **Linear time.** `Parse` finds the pipes of the header fields a word at a time, and with
  `bytes.IndexByte` once a backslash precedes one; it finds each `=` with `bytes.IndexByte` and
  walks back over a key at most once for each `=`, so `=` runs, long keys, escaped pipes and
  backslash runs cost time linear in the input; the unescapers and the escapers are linear too.
  Tests time each such shape at two sizes and fail on a cost that grows faster than the input.
- **Bounded memory.** `Parse` allocates only the pair storage, 16 bytes a pair up to the limit it is
  given, and the `*ParseError` of a fault, and it copies no input. Its stack use is constant:
  nothing recurses. An Event drops owned bytes past 64 KiB when its next copy or text needs at most
  64 KiB, and keeps them otherwise.
- **A declared pair limit.** Every `Parse` names the most pairs it accepts, and past it fails with
  `ErrExtOverflow`, the pairs before kept. `MaxExtensions` (256) is the limit for a caller that
  declares none, and the limit of `UnmarshalText`.
- **An input bound.** `Parse` refuses an input longer than 4294967295 bytes, the most a `Span`
  indexes, with `ErrInputTooLarge` before reading it, and `UnmarshalText` before copying it.
- **No panic on any input.** `Parse`, `UnmarshalText` and the unescapers return on every input; fuzz
  targets check them against a reference parser and a reference unescaper written apart from the
  code. The panics the godoc names come from a broken precondition only: a nil destination for
  `CloneTo`, and `Error` on a `ParseError` that holds no `Err`.
- **Memory safety.** No file imports `unsafe`, tests included, which a lint rule enforces; the
  module has no cgo and requires no module.
- **Views.** `Bytes`, and the unescapers for a field without a backslash, return slices of the input
  whose capacity ends with the field, so an append copies instead of writing over the input; the
  unescapers write only `dst`.
- **One reading.** The seventh `|` is required, so an extension never becomes the Severity field; a
  `|` that an odd run of backslashes precedes stays in its field; a value ends only where a run of
  key bytes and an `=` start after a space. `Ext` and `ExtString` return the last pair of a repeated
  key, and `ExtAt` and `All` show every pair, so a caller that checks every pair sees the
  repetition.
- **Errors.** A `ParseError` holds the sentinel and the byte offset, and no error text holds input
  bytes.
- **Output.** `AppendText` and `MarshalText` write only an Event whose text reads back to it: they
  refuse an incomplete header, more than `MaxExtensions` pairs, a last value that a cut at a pair
  limit left ending in a space, CR or LF, and text that is not UTF-8. `AppendEscapedHeader` and
  `AppendEscapedExtValue` escape every byte that would end a field or a value early, and write CR
  and LF so that no event spans two lines.

## Known Limits

| Parameter | Limit |
|-----------|-------|
| Pairs per `Parse` | the caller's `maxExtensions`; a limit of 0 or less admits no pair |
| `MaxExtensions` | 256 |
| Pair storage | 16 bytes a pair: 16 pairs, or the limit when lower, then twice as many, at least 16, up to the limit; a copy grows it to the pair count of its source |
| Input length | 4294967295 bytes |
| Version token | 1 to 4 digits without a leading zero, 0 to 9999 |
| Owned bytes of `CloneTo` and `UnmarshalText` | 64 KiB kept; more until the next copy or text that needs at most 64 KiB |
| Work per input | linear in the input |

`Parse` refuses an input past the pair limit it is given, the input length or the version token with
the sentinel of that limit, and `UnmarshalText`, `AppendText` and `MarshalText` refuse more than
`MaxExtensions` pairs.

## Out of Scope

- Authenticity and integrity: CEF carries no signature, so an event holds what its sender wrote, and
  the transport's security is the caller's.
- Finding `CEF:` in a syslog line and reading the syslog header.
- The meaning of values: addresses, times, numbers and the keys of the CEF dictionary are text to
  go-cef, and their checks are the caller's.
- Output a caller writes from decoded fields: they may hold any byte, the CR and LF of `\r` and `\n`
  and bytes that are not UTF-8 included, so a caller escapes them for its own format.
- Limits above the ones a caller declares, and a write to an input or an Event while another
  goroutine reads it.

## Continuous Verification

- `make ci` runs every gate below but CodeQL and fuzzing, and the workflows run the same Makefile
  targets.
- `make modcheck` (`go mod download`, `go mod verify`, `go mod tidy -diff`), `make vet`, `make test`
  and `make test386` (the tests with `-shuffle=on` and their allocation counts, on amd64 and on
  386), `make cover` (the tests with `-race` and `-shuffle=on`, failing on any statement they leave
  uncovered) and `make bench-smoke` (100 iterations of every benchmark) on Go 1.25.14 and Go 1.27.3
  (`test.yml`).
- `golangci-lint` v2.14.0, built with Go 1.27.3 (`lint.yml`, `make lint`), with the repository
  `.golangci.yml`: every linter of its enable list and the `gofmt` and `goimports` formatters,
  `gosec` included, test files linted. The `depguard` rule `unsafe` denies `unsafe` to every file.
  Every `nolint` directive names its linter and gives a reason.
- `deadcode -test` v0.50.0 (`lint.yml`, `make deadcode`): no function that neither a test nor an
  entry point reaches.
- `govulncheck` v1.8.0 and CodeQL with the `security-and-quality` suite (`security.yml`).
- Every action is pinned by commit with its version, every workflow has top-level permissions no
  wider than `contents: read` (CodeQL's in `security.yml`), and every checkout leaves no credentials
  behind.
- Native fuzzing (`fuzz.yml`, weekly, and `make fuzz`) over every `Fuzz` function, listed by `make
  fuzz-list`, each with a reference parser, the tables of Version 27 written as literals, `strconv`,
  `utf8` or a reference unescaper as its oracle.
