// Package cef provides a zero-allocation CEF (Common Event Format) parser.
//
// Supports CEF:0, CEF:1, and future versions per the ArcSight CEF spec (v26).
//
// # Usage
//
//	p := cef.NewParser()
//	e, err := p.Parse(input)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(e.Text(e.Vendor))
//	if src, ok := e.ExtString("src"); ok {
//	    fmt.Println(e.Text(src))
//	}
//
// # Allocation model
//
// Parser.Parse and the zero-alloc accessors (Bytes, Ext, ExtString, ExtAt,
// AppendBytes, AppendText into a pre-sized buffer) do not allocate on
// successful paths. Text and MarshalText allocate the returned string/buffer.
// Clone/CloneTo allocate only the minimal byte range covering parsed spans.
// The iter.Seq2 returned by All allocates the closure; prefer ExtAt in a loop.
//
// # Lifetime
//
// The *Event returned by Parse aliases the input buffer and is valid until
// the next Parse call on the same Parser. Use Clone or CloneTo to retain a
// result across further Parse calls.
//
// # Concurrency
//
// A Parser is not safe for concurrent use. A parsed *Event is safe for
// concurrent readers as long as no one writes to it or to the underlying
// input buffer.
package cef
