# go-cef

> A Common Event Format parser and writer for Go. `Parse` reads an event where it lies, as spans of
> the input, and allocates nothing but the `*ParseError` of a fault once the Event's pair storage
> holds the event's pairs.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![Lint](https://github.com/ubyte-source/go-cef/actions/workflows/lint.yml/badge.svg)](https://github.com/ubyte-source/go-cef/actions/workflows/lint.yml)
[![Test](https://github.com/ubyte-source/go-cef/actions/workflows/test.yml/badge.svg)](https://github.com/ubyte-source/go-cef/actions/workflows/test.yml)
[![Security](https://github.com/ubyte-source/go-cef/actions/workflows/security.yml/badge.svg)](https://github.com/ubyte-source/go-cef/actions/workflows/security.yml)
[![Fuzz](https://github.com/ubyte-source/go-cef/actions/workflows/fuzz.yml/badge.svg)](https://github.com/ubyte-source/go-cef/actions/workflows/fuzz.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubyte-source/go-cef.svg)](https://pkg.go.dev/github.com/ubyte-source/go-cef)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)](go.mod)

## Features

- Events of Version 27 of the CEF Implementation Standard: [Implementing ArcSight Common Event
  Format (CEF), Version
  27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.3/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf),
  OpenText, July 2024.
- `(*Event).Parse` reads the version, and the six header fields and extension pairs as `Span`s of
  the input: no copy, and no allocation but the `*ParseError` of a fault into an Event whose pair
  storage holds the event's pairs.
- The caller declares the most pairs it accepts on every call, and the pair storage `Parse` grows
  stops at that limit; `MaxExtensions` (256) is the limit for a caller that declares none.
- Fields keep their escape sequences. `UnescapeHeader` and `UnescapeExtValue` decode one field into
  a buffer of the caller's or in place, and return the field itself when it holds no backslash.
- `AppendEscapedHeader`, `AppendEscapedExtValue` and `ValidKey` write events that `Parse` reads back
  field by field.
- Every fault of `Parse` is a `*ParseError` with one sentinel and the byte offset, and the Event
  keeps what precedes the fault.
- `SeverityLevel` classifies the Severity field once, by the table of Version 27.
- `Clone`, `CloneTo`, `AppendText`, `MarshalText` and `UnmarshalText` keep an event past its input
  or carry it as text.
- Time and memory linear in the input, no panic on any input, no `unsafe`, no cgo and no
  dependencies.

Requires **Go 1.25+**.

## Install

```bash
go get github.com/ubyte-source/go-cef
```

## Quick start

`Parse` takes the input and the most pairs the caller accepts:

```go
line := []byte(`CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|` +
	`src=10.0.0.1 dst=2.1.2.2 spt=1232`)
var e cef.Event
if err := e.Parse(line, cef.MaxExtensions); err != nil {
	fmt.Println(err)
	return
}
src, _ := e.ExtString("src")
fmt.Println(e.Text(e.DeviceVendor()), e.Text(e.Name()), e.Text(src))
// Output: Security worm successfully stopped 10.0.0.1
```

Declare the Event once and parse each line into it: `Parse` keeps the pair storage of the Event, so
once the storage holds the pairs of an event, events of as many pairs or fewer parse with no
allocation but the `*ParseError` of a fault. `DeviceVendor`, `DeviceProduct`, `DeviceVersion`,
`DeviceEventClassID`, `Name` and `Severity` return the spans of the six header fields, and `Version`
the version. `Ext` finds a pair by a `[]byte` key and `ExtString` by a string key; `ExtAt` and `All`
walk the pairs in input order. `Bytes` gives the bytes of a span as a view of the input, `Text` a
string copy and `AppendBytes` appends them to a buffer.

The spans keep the escape sequences of the input. `UnescapeHeader` decodes `\\` and `\|` in a header
field:

```go
fmt.Println(string(cef.UnescapeHeader([]byte(`detected a \| in message`), nil)))
// Output: detected a | in message
```

`UnescapeExtValue` decodes `\\`, `\=`, `\n` and `\r` in a value:

```go
fmt.Printf("%q\n", cef.UnescapeExtValue([]byte(`a\=b\nc`), nil))
// Output: "a=b\nc"
```

Both return the field itself, its capacity capped, when it holds no backslash, and otherwise decode
it over `dst[:0]`; `dst` may be the field itself, which decodes it in place, and they allocate once
only when `dst` has less room than the field. A backslash before any other byte stays.

`SeverityLevel` reads the Severity field once and returns its `Level`, its number and whether the
field is an integer 0 to 10 or a level name in any letter case:

```go
var e cef.Event
if err := e.Parse([]byte("CEF:0|Vendor|Product|1.0|100|Name|very-high|"), cef.MaxExtensions); err != nil {
	fmt.Println(err)
	return
}
level, num, ok := e.SeverityLevel()
fmt.Println(level, num, ok)
// Output: Very-High 10 true
```

## Writing CEF

`AppendEscapedHeader` escapes `\` and `|` and writes each CR or LF of a header field as a space;
`AppendEscapedExtValue` escapes `\` and `=` and writes CR and LF as `\r` and `\n`; `ValidKey`
reports whether a key is one `Parse` reads:

```go
line := []byte("CEF:0|")
for _, field := range []string{"Vendor", "Product|X", "1.0", "100", "Name", "5"} {
	line = append(cef.AppendEscapedHeader(line, field), '|')
}
line = cef.AppendEscapedExtValue(append(line, "msg="...), "a=b\nc")
fmt.Println(string(line), cef.ValidKey("msg"))
// Output: CEF:0|Vendor|Product\|X|1.0|100|Name|5|msg=a\=b\nc true
```

The three take a string or a byte slice, named types included, and allocate nothing when `dst` has
room. `Parse` drops the trailing spaces of the last value of an event, so a writer that keeps them
puts that pair before another.

## Ownership and lifetime

- An Event reads the input of its last `Parse` in place until its next `Parse`: the input is not to
  be written while the Event is read, and `Reset` drops the Event's reference to it and keeps the
  storage, for an Event kept in a pool.
- `Bytes` and the views `UnescapeHeader` and `UnescapeExtValue` return for a clean field are slices
  of the input whose capacity ends with the field, so an append to one copies instead of writing
  over the input.
- `Clone` returns a new Event that owns its bytes and pairs: one allocation for the Event, one for
  the bytes from its first header field to the end of its last span when there are any, and one for
  its pairs when there are any. `CloneTo` writes the copy into an Event of the caller's, reusing its
  storage, with no allocation when the storage has room, unless it drops owned bytes past 64 KiB as
  below; `e.CloneTo(e)` makes `e` own its bytes.
- `UnmarshalText` copies the text into bytes the Event owns and parses the copy under
  `MaxExtensions`.
- `CloneTo` and `UnmarshalText` write only bytes the Event owns, which they reuse unless too few, or
  more than 64 KiB for a copy that needs no more. A view of those bytes lasts until the next
  `CloneTo` into the Event or `UnmarshalText`.
- A value copy of an Event shares its pairs and owned bytes with the Event it copies. After a
  `Parse`, `CloneTo` or `UnmarshalText` into one of the two, the other is not to be read, because
  its pairs then index another input. `Clone` gives an independent copy.
- The zero Event is ready to use. An Event is safe for concurrent readers while nobody writes it
  (`Parse`, `UnmarshalText`, `Reset`, `CloneTo` into it) or its input.

With `e` parsed from `packet`, a copy made by `CloneTo` reads the same event after the packet
changes:

```go
e.CloneTo(&kept)
copy(packet, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
act, _ := kept.ExtString("act")
fmt.Println(kept.Text(kept.DeviceVendor()), kept.Text(act))
// Output: Vendor allow
```

`AppendText` writes an Event as text that `UnmarshalText` reads back to an equal Event, with the
spaces after `CEF:` and around the extension dropped:

```go
line := []byte("CEF:  0|Vendor|Product|1.0|100|Name|5|  src=10.0.0.1   \r\n")
var e cef.Event
if err := e.Parse(line, cef.MaxExtensions); err != nil {
	fmt.Println(err)
	return
}
text, err := e.AppendText(nil)
fmt.Printf("%s %v\n", text, err)
// Output: CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1 <nil>
```

## Errors

Every fault of `Parse`, and so of `UnmarshalText`, is a `*ParseError`: `Err` holds the sentinel,
which `errors.Is` matches through `Unwrap`, and `Position` the zero-based byte offset of the fault
in the input.

```go
var e cef.Event
err := e.Parse([]byte("CEF:0|Vendor|Product"), cef.MaxExtensions)
fmt.Println(err, errors.Is(err, cef.ErrIncompleteHeader))
// Output: cef: incomplete CEF header at byte 20 true
```

| Sentinel | Returned by | When |
|----------|-------------|------|
| `ErrEmpty` | `Parse` | the input has no bytes |
| `ErrPrefix` | `Parse` | the input does not start with `CEF:`, a syslog header included |
| `ErrVersion` | `Parse` | the version token is not 1 to 4 digits without a leading zero, followed by `\|` or the end of the input |
| `ErrIncompleteHeader` | `Parse`; `AppendText`, `MarshalText` | the input ends before the seventh unescaped `\|`; an Event whose `HeaderComplete` is false |
| `ErrExtKey` | `Parse` | a non-empty extension holds no `=`, or its first key is not one or more key bytes |
| `ErrExtOverflow` | `Parse`; `AppendText`, `MarshalText` | a pair past the limit `Parse` was given; an Event of more than `MaxExtensions` pairs, or whose last value a cut at a pair limit left ending in a space, CR or LF |
| `ErrInputTooLarge` | `Parse` | the input is longer than 4294967295 bytes |
| `ErrInvalidUTF8` | `AppendText`, `MarshalText` | the event's text is not UTF-8 |

The text methods return the sentinel itself, and leave `dst` as it was. On a fault `Parse` leaves
the Event with what precedes the fault: the version and the header fields it read, with
`HeaderComplete` false, before the seventh `|`, and after it `HeaderComplete` true and the pairs
before the fault. After `ErrInputTooLarge` the Event is the zero Event, and after `ErrVersion` its
`Version` is 0.

## Behaviour

- The input starts at `CEF:`, and spaces between `CEF:` and the version are skipped. A syslog header
  before `CEF:` fails with `ErrPrefix`: stripping it is the caller's job, as below.
- The version and each of the six header fields end at a `|` that no odd run of backslashes
  precedes, and an escaped `|` belongs to the field. The seventh `|` is required, and the extension
  runs from it to the end of the input.
- The last duplicate key wins: `Ext` and `ExtString` return the value of the last pair with the key,
  while `ExtAt` and `All` show every pair.
- The trailing spaces, CRs and LFs of the extension are dropped, so the last value never ends in
  one, and the spaces before the first key are skipped.
- A value runs to the space before the next run of key bytes that a space precedes and an `=` ends.
  The spaces before a key, except the one that separates the pairs, belong to the value before it:
  `a=1   b=2` gives `a` the value `1` and two spaces. An empty value, as in `src= dst=1`, is an
  empty span.
- A key is one or more of A-Z, a-z, 0-9, `.`, `_`, `-`, `[` and `]`, the bytes `ValidKey` accepts; a
  tab separates no pairs.
- `Parse` accepts inputs Version 27 does not admit and reads them as stated here: an unescaped `=`
  stays in its value unless key bytes and a space precede it, an unknown escape stays as it is,
  bytes that are not UTF-8 pass through, spaces before the version are skipped, a key may hold `.`,
  `_`, `-`, `[` and `]`, a raw CR or LF stays in a header field or a value, and a header field may
  be longer than its Version 27 size.

With a syslog header, find `CEF:` first:

```go
packet := []byte(`<134>Oct 27 10:00:00 fw1 CEF:0|Vendor|Product|1.0|100|Name|5|act=allow`)
start := max(bytes.Index(packet, []byte("CEF:")), 0)
var e cef.Event
err := e.Parse(packet[start:], cef.MaxExtensions)
act, _ := e.ExtString("act")
fmt.Println(err, e.Text(act))
// Output: <nil> allow
```

### Severity

`SeverityLevel` reads the Severity field by the table of Version 27. A number is one digit or `10`,
with no sign, space or leading zero; a name matches in any letter case.

| Severity field | `Level` | number |
|----------------|---------|-------:|
| `0` | `LevelUnknown` | 0 |
| `1` to `3` | `LevelLow` | the field |
| `4` to `6` | `LevelMedium` | the field |
| `7` and `8` | `LevelHigh` | the field |
| `9` and `10` | `LevelVeryHigh` | the field |
| `Unknown` | `LevelUnknown` | 0 |
| `Low` | `LevelLow` | 3 |
| `Medium` | `LevelMedium` | 6 |
| `High` | `LevelHigh` | 8 |
| `Very-High` | `LevelVeryHigh` | 10 |
| anything else | `LevelUnknown`, and `ok` false | 0 |

`Level.String` returns the name of a level as the Severity field writes it, `Unknown`, `Low`,
`Medium`, `High` or `Very-High`, with no allocation, and `Level(N)` for any other value.

### Text round trip

`AppendText` and `MarshalText` write `CEF:`, the version, the six header fields and the pairs as the
input holds them, escapes kept, with one `|` after each field. They refuse an Event whose text would
not read back to it, in this order: `ErrIncompleteHeader` unless `HeaderComplete`, then
`ErrExtOverflow` for an Event of more than `MaxExtensions` pairs or one whose last value a cut at a
pair limit left ending in a space, CR or LF, then `ErrInvalidUTF8` when the text is not UTF-8.
`AppendText` allocates nothing when `dst` has room, and `MarshalText` allocates the text once.

## Operational limits

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Pairs per `Parse` | the caller's `maxExtensions` | `Parse` fails with `ErrExtOverflow` at the first pair past the limit and keeps the pairs before it; a limit of 0 or less admits no pair. |
| `MaxExtensions` | 256 | The limit of `UnmarshalText`, the most pairs `AppendText` and `MarshalText` write, and the limit to pass to `Parse` for a caller that declares none. |
| Pair storage | 16 bytes a pair: 16 pairs, or the limit when lower, for the first pair, then twice as many, at least 16, up to the limit; a copy grows it to the pair count of its source | An Event keeps its storage across `Parse` and `Reset`, so memory follows the largest limit the Event is given or the largest event copied into it, and a warm Event parses with no allocation but the `*ParseError` of a fault. |
| Input length | 4294967295 bytes | The most a `Span` indexes: `Parse` refuses a longer input with `ErrInputTooLarge` before reading it, and `UnmarshalText` before copying it. |
| Version token | 1 to 4 digits without a leading zero, 0 to 9999 | Any other token fails with `ErrVersion`. |
| Owned bytes of `CloneTo` and `UnmarshalText` | 64 KiB kept | An Event drops owned bytes past 64 KiB when its next copy or text needs at most 64 KiB, and keeps them through `Parse` and `Reset` until then. |
| Work per input | linear in the input | `Parse`, the unescapers and the escapers run in time linear in their input, `=` runs, long keys, escaped pipes and backslash runs included. |

## Performance

### Benchmarks

Medians of ten runs of `go test -run '^$' -bench . -benchmem -benchtime 300ms -count 10` with Go
1.27.2 on linux/amd64, an Intel Xeon Gold 6442Y pinned to 4 cores, default build, no PGO.
`EventParse` parses into a warm Event: `Pairs58`, `Pairs106` and `Pairs171` are events of that many
pairs, `EqualsRun` a value of 1000 `=` and `EscapedPipes` a header field of 1000 escaped pipes.
`EventExtString` looks up the first, a middle and the last of 17 pairs and a missing key,
`EventClone` and `EventCloneTo` copy events of 10 and 58 pairs, and `Clean`, `Typical` and `Dense`
are fields with no escape, a few and nothing but escapes. The cases that allocate are the ones that
return a new string, byte slice or Event by design.

| Benchmark | Time [ns/op] | Throughput [MB/s] | Allocated [B/op] | Allocations [allocs/op] |
|-----------|-------------:|------------------:|-----------------:|------------------------:|
| `EventParse/Minimal` | 28.4 | 1412 | 0 | 0 |
| `EventParse/HeaderOnly` | 25.2 | 1431 | 0 | 0 |
| `EventParse/CiscoASA` | 139 | 1156 | 0 | 0 |
| `EventParse/PaloAlto` | 153 | 1229 | 0 | 0 |
| `EventParse/Escaped` | 102 | 1328 | 0 | 0 |
| `EventParse/Pairs58` | 660 | 1466 | 0 | 0 |
| `EventParse/Pairs106` | 1156 | 1521 | 0 | 0 |
| `EventParse/Pairs171` | 1752 | 1644 | 0 | 0 |
| `EventParse/EqualsRun` | 8478 | 358 | 0 | 0 |
| `EventParse/EscapedPipes` | 682 | 2959 | 0 | 0 |
| `EventAccessors` | 2.51 | | 0 | 0 |
| `EventExt` | 6.84 | | 0 | 0 |
| `EventExtString/key0` | 12.8 | | 0 | 0 |
| `EventExtString/key8` | 7.71 | | 0 | 0 |
| `EventExtString/key16` | 7.03 | | 0 | 0 |
| `EventExtString/missing` | 13.0 | | 0 | 0 |
| `EventExtAt` | 73.7 | | 0 | 0 |
| `EventAll` | 118 | | 0 | 0 |
| `EventBytes` | 1.45 | | 0 | 0 |
| `EventText` | 12.2 | | 8 | 1 |
| `EventAppendBytes` | 3.10 | | 0 | 0 |
| `EventSeverityLevel/7` | 2.25 | | 0 | 0 |
| `EventSeverityLevel/0` | 2.26 | | 0 | 0 |
| `EventSeverityLevel/High` | 2.54 | | 0 | 0 |
| `EventSeverityLevel/Very-High` | 3.67 | | 0 | 0 |
| `EventSeverityLevel/bogus` | 2.53 | | 0 | 0 |
| `LevelString` | 1.22 | | 0 | 0 |
| `UnescapeHeader/Clean` | 5.01 | 9981 | 0 | 0 |
| `UnescapeHeader/Typical` | 38.8 | 1339 | 0 | 0 |
| `UnescapeHeader/Dense` | 842 | 1217 | 0 | 0 |
| `UnescapeExtValue/Clean` | 5.08 | 9845 | 0 | 0 |
| `UnescapeExtValue/Typical` | 37.8 | 1375 | 0 | 0 |
| `UnescapeExtValue/Dense` | 847 | 1210 | 0 | 0 |
| `AppendEscapedHeader/Clean` | 24.6 | 2033 | 0 | 0 |
| `AppendEscapedHeader/Escaped` | 30.6 | 1242 | 0 | 0 |
| `AppendEscapedExtValue/Clean` | 23.0 | 2173 | 0 | 0 |
| `AppendEscapedExtValue/Escaped` | 36.3 | 1270 | 0 | 0 |
| `ValidKey` | 15.2 | | 0 | 0 |
| `EventClone/10` | 155 | | 464 | 3 |
| `EventClone/58` | 550 | | 2176 | 3 |
| `EventCloneTo/10` | 26.2 | | 0 | 0 |
| `EventCloneTo/58` | 75.9 | | 0 | 0 |
| `EventAppendText` | 32.6 | | 0 | 0 |
| `EventMarshalText` | 71.4 | | 112 | 1 |
| `EventUnmarshalText` | 91.7 | | 0 | 0 |
| `EventReset` | 1.87 | | 0 | 0 |
| `EventString` | 215 | | 288 | 1 |
| `ExtPairString` | 54.9 | | 24 | 1 |
| `SpanString` | 33.2 | | 16 | 1 |
| `SpanLen` | 0.639 | | 0 | 0 |
| `VersionString/1` | 2.22 | | 0 | 0 |
| `VersionString/9999` | 15.4 | | 4 | 1 |
| `ParseErrorError` | 34.2 | | 48 | 1 |
| `ParseErrorUnwrap` | 1.01 | | 0 | 0 |
| `ConstErrorError` | 1.62 | | 0 | 0 |
| `WordAt/Own` | 17.0 | 4364 | 0 | 0 |
| `WordAt/SharedForm` | 27.1 | 2734 | 0 | 0 |
| `TextWord/Own` | 15.5 | 3092 | 0 | 0 |
| `TextWord/SharedForm` | 23.2 | 2073 | 0 | 0 |

### Other Go CEF parsers

Seven other Go CEF parsers, each at a pinned version and ren3gadem4rm0t/cef-parser-go in two
configurations, parse six shapes in one harness: `header`, an event without pairs; `firewall`, a
firewall event of 26 pairs; `panos106`, a PAN-OS traffic event of 106 pairs; `escapes`, a process
event whose paths and command lines hold many escapes; `longvalues`, values of up to 4000 bytes; and
`spec7`, the seven examples of Version 27 in turn. Each library makes the call its users make, into
a reused parser or event where it has one, and a library's result counts only the fields it returns
as Version 27 reads them: the version, the six header fields and every pair. go-cef returns spans
with the escapes kept, so `go-cef+decode` adds `UnescapeHeader` on the six header fields and
`UnescapeExtValue` on every value, into reused buffers, which is what the others return; they build
strings or maps for every field by design. Medians of ten interleaved rounds of `-benchtime 1s` with
Go 1.27.2, `GOAMD64=v1`, `CGO_ENABLED=0` and no PGO, pinned to 4 cores of the Intel Xeon Gold 6442Y
above, on 2026-10-27; a mark † flags a library that returns a wrong or missing field, or an error,
on that shape.

| Library | Version | Call timed |
|---------|---------|------------|
| go-cef | this module | Parse into a reused Event |
| go-cef+decode | this module | Parse, then the unescapers on every field |
| Elastic Beats decode_cef | v9.5.5 | the Unpack method of its Event, into a reused Event |
| OpenTelemetry Collector contrib, transform processor | v0.164.1 | the body of its ParseCEF function |
| Datadog Agent, logs syslog parser | 7.84.6 | its ParseCEFLEEF function |
| VictoriaLogs, logstorage | v1.53.0 | the CEF path of its syslog parser, reused |
| lynxdb, engine unpack | v0.2.5 | the Parse method of its CEF parser, keeping every value |
| pcktdmp/cef | v0.6.1 | the Read method of its event |
| ren3gadem4rm0t/cef-parser-go | v0.2.0 | its default ParseCEF, and its fast configuration |

Time per event, lower is faster:

| Library | header [ns] | firewall [ns] | panos106 [ns] | escapes [ns] | longvalues [ns] | spec7 [ns] |
|---------|------------:|--------------:|--------------:|-------------:|----------------:|-----------:|
| go-cef | 31.9 | 425 | 1608 | 390 | 1018 | 462 |
| go-cef+decode | 62.6 | 631 | 2351 | 1049 | 2122 | 883 |
| VictoriaLogs | 87.5 | 1548 | 6309 | 2163 | 3048 | 1796 † |
| Datadog Agent | 198 | 1854 | 6765 | 3444 | 13660 | 3900 |
| Elastic Beats | 202 | 6039 | 32477 † | 11042 | 27930 | 6244 |
| OpenTelemetry | 972 | 3376 | 14242 | 5503 | 27537 | 9370 |
| lynxdb | 176 | 2830 † | 11567 † | 5316 † | 37215 † | 5633 † |
| pcktdmp | 979 | 22278 | 82960 | 37520 † | 380282 | 24474 |
| ren3gadem4rm0t, fast | 292 | 6120 † | 22714 † | 6849 † | 33697 † | 5741 † |
| ren3gadem4rm0t | 19190 | 22406 † | 64242 † | 25318 † | 129468 † | 130658 † |

Allocations per event: go-cef and go-cef+decode allocate nothing on every shape, VictoriaLogs and
lynxdb nothing on `header` only, and the others from 1 (Beats, `header`) to 1735 (ren3gadem4rm0t,
`spec7`).

Fields right, out of the fields of the shape:

| Library | header | firewall | panos106 | escapes | longvalues | spec7 |
|---------|-------:|---------:|---------:|--------:|-----------:|------:|
| go-cef | 7/7 | 33/33 | 113/113 | 25/25 | 13/13 | 67/67 |
| VictoriaLogs | 7/7 | 33/33 | 113/113 | 25/25 | 13/13 | 66/67 |
| Datadog Agent | 7/7 | 33/33 | 113/113 | 25/25 | 13/13 | 67/67 |
| Elastic Beats | 7/7 | 33/33 | 112/113 | 25/25 | 13/13 | 67/67 |
| OpenTelemetry | 7/7 | 33/33 | 113/113 | 25/25 | 13/13 | 67/67 |
| lynxdb | 7/7 | 32/33 | 111/113 | 15/25 | 12/13 | 64/67 |
| pcktdmp | 7/7 | 33/33 | 113/113 | 24/25 | 13/13 | 67/67 |
| ren3gadem4rm0t, fast | 7/7 | 32/33 | 100/113 | 13/25 | 10/13 | 60/67 |
| ren3gadem4rm0t | 7/7 | 0/33, error | 100/113 | 0/25, error | 10/13 | 35/67 |

Five rules of Version 27 that the examples do not reach (the spaces a value keeps before the next
key, trailing spaces, a backslash before a header pipe, UTF-8 text, and a line without the pipe
after Severity, which a parser refuses) give 36 fields right of 36 to go-cef and Beats, 35 to
Datadog, VictoriaLogs and pcktdmp, 34 to OpenTelemetry and to the fast configuration of
ren3gadem4rm0t, 27 to lynxdb and 18 to ren3gadem4rm0t. Beats decode_cef is under the Elastic License
2.0: it is measured, and none of its code or test data is in this module.
ren3gadem4rm0t/cef-parser-go has few importers and is measured for completeness.

## Testing and gates

`make ci` runs every gate of the workflows but CodeQL and fuzzing; `make help` lists the targets.

```bash
make test       # the tests, allocation counts included
make test386    # the tests of the 32-bit build
make race       # the tests under the race detector, which skips the counts, writing coverage.out
make cover      # race, then fails on any statement the tests leave uncovered
make lint       # golangci-lint with .golangci.yml
make deadcode   # deadcode -test
make vuln       # govulncheck
make bench      # every benchmark
make fuzz       # every fuzz target, FUZZTIME each (30s by default)
```

## Design principles

1. The caller owns the Event and declares the pair limit on every call: no parser type, no option
   and no mode.
2. One contract for every input: `Parse` returns nil or the fault, and the Event keeps what precedes
   the fault.
3. Zero allocation on every path the result allows, each count asserted by a test.
4. Fields are read where they lie and decoded only on request.
5. No dependencies: pure Go, no cgo, no `unsafe` and no code generation.

## Project layout

```
go-cef/
├── doc.go             # Package documentation
├── cef.go             # Event, its accessors, lookups, views, copies and text; Span, ExtPair and Version
├── parse.go           # Parse, MaxExtensions and the header grammar
├── extensions.go      # The extension pairs and their storage
├── severity.go        # Level and SeverityLevel
├── unescape.go        # UnescapeHeader and UnescapeExtValue
├── escape.go          # Text, AppendEscapedHeader, AppendEscapedExtValue and ValidKey
├── errors.go          # ParseError and the sentinels
├── *_test.go          # One sibling per source file; doc_test.go holds the shared fixtures and the reference parser
├── testdata/          # Vendor and grammar events, the conformance cases and their provenance
├── .golangci.yml      # Linter configuration
└── Makefile           # The gates, the benchmarks and the fuzz runs
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For security issues, see [SECURITY.md](SECURITY.md).

## Versioning

We use [SemVer](https://semver.org/). Releases are tracked in the repository
[tags](https://github.com/ubyte-source/go-cef/tags).

## Authors

- **Paolo Fabris** — [ubyte.it](https://ubyte.it/)

See also the list of [contributors](https://github.com/ubyte-source/go-cef/contributors).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Support

If go-cef is useful for your SIEM pipeline, consider supporting the work:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-orange?style=for-the-badge&logo=buy-me-a-coffee)](https://coff.ee/ubyte)
