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
//	fmt.Println(e.Text(e.Severity))
package cef
