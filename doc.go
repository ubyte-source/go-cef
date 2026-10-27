// Package cef reads and writes Common Event Format events, Version 27 of the ArcSight
// standard, where they lie: Parse reads one event that starts with "CEF:" into an Event
// that holds its version, and its six header fields and extension pairs as Spans of the
// input, with no copy and, once the Event's pair storage holds the event's pairs, no
// allocation but the *ParseError of a fault; the caller declares the most pairs it
// accepts. Fields keep their escape sequences, which UnescapeHeader and
// UnescapeExtValue decode and AppendEscapedHeader and AppendEscapedExtValue write, and
// ValidKey checks a key. On a fault Parse returns a *ParseError wrapping one sentinel
// and the Event keeps what precedes the fault. Clone and CloneTo give an Event that
// owns its bytes, and AppendText writes an Event as text that Parse reads back to an
// equal Event. CloneTo and UnmarshalText write only bytes the Event owns, which they
// reuse unless too few, or more than 64 KiB for a copy that needs no more. An Event
// reads the input of its last Parse in place until its next Parse, and a view of its
// own bytes lasts until the next CloneTo into it or UnmarshalText; the zero Event is
// ready to use, and an Event is safe for concurrent readers while nobody writes it
// (Parse, UnmarshalText, Reset, CloneTo into it) or its input. A value copy of an Event
// shares its pairs and owned bytes: after a Parse, CloneTo or UnmarshalText into one
// copy, the other is not to be read, because its pairs then index another input, and
// Clone gives an independent copy.
package cef
