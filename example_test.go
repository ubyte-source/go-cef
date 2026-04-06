package cef_test

import (
	"fmt"
	"sync"

	"github.com/ubyte-source/go-cef"
)

func ExampleNewParser() {
	p := cef.NewParser()
	input := `CEF:0|Security|ThreatManager|1.0|100|` +
		`worm successfully stopped|10|` +
		`src=10.0.0.1 dst=2.1.2.2 spt=1232`
	e, err := p.Parse([]byte(input))
	if err != nil {
		panic(err)
	}
	fmt.Println("Version:", e.Version)
	fmt.Println("Vendor:", e.Text(e.Vendor))
	fmt.Println("Product:", e.Text(e.Product))
	fmt.Println("Severity:", e.Text(e.Severity))
	if src, ok := e.ExtString("src"); ok {
		fmt.Println("Source:", e.Text(src))
	}
	// Output:
	// Version: 0
	// Vendor: Security
	// Product: ThreatManager
	// Severity: 10
	// Source: 10.0.0.1
}

func ExampleNewParser_bestEffort() {
	p := cef.NewParser(cef.WithBestEffort())
	// Truncated input — missing some header fields.
	e, err := p.Parse([]byte(`CEF:0|Vendor|Product`))
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Version:", e.Version)
	fmt.Println("Vendor:", e.Text(e.Vendor))
	fmt.Println("Valid:", e.Valid())
	// Output:
	// Error: incomplete CEF header [col 20]
	// Version: 0
	// Vendor: Vendor
	// Valid: false
}

func ExampleEvent_SeverityLevel() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|V|P|1|100|N|8|`))
	if err != nil {
		panic(err)
	}
	num, _ := e.SeverityNum()
	level, _ := e.SeverityLevel()
	fmt.Println("Severity num:", num)
	fmt.Println("Severity level:", level)
	// Output:
	// Severity num: 8
	// Severity level: High
}

func ExampleEvent_ExtString() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=10.0.0.1 dst=2.1.2.2 msg=hello world`))
	if err != nil {
		panic(err)
	}

	keys := []string{"src", "dst", "msg", "nonexistent"}
	for _, k := range keys {
		if span, ok := e.ExtString(k); ok {
			fmt.Printf("%s = %s\n", k, e.Text(span))
		} else {
			fmt.Printf("%s = (not found)\n", k)
		}
	}
	// Output:
	// src = 10.0.0.1
	// dst = 2.1.2.2
	// msg = hello world
	// nonexistent = (not found)
}

func ExampleNewParser_pool() {
	// Use sync.Pool in high-throughput pipelines to amortize Parser
	// allocation across goroutines.
	pool := sync.Pool{
		New: func() any { return cef.NewParser() },
	}

	input := []byte(`CEF:0|V|P|1|100|N|5|src=10.0.0.1`)

	p, ok := pool.Get().(*cef.Parser)
	if !ok {
		panic("type assertion failed")
	}
	e, err := p.Parse(input)
	if err != nil {
		panic(err)
	}
	fmt.Println("Vendor:", e.Text(e.Vendor))
	pool.Put(p)
	// Output:
	// Vendor: V
}

func ExampleEvent_AppendBytes() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=10.0.0.1 dst=2.1.2.2`))
	if err != nil {
		panic(err)
	}

	// AppendBytes is zero-alloc when dst has sufficient capacity.
	buf := make([]byte, 0, 64)
	if src, ok := e.ExtString("src"); ok {
		buf = e.AppendBytes(buf, src)
	}
	fmt.Println(string(buf))
	// Output:
	// 10.0.0.1
}

func ExampleEvent_All() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=10.0.0.1 dst=2.1.2.2`))
	if err != nil {
		panic(err)
	}

	for key, val := range e.All() {
		fmt.Printf("%s = %s\n", e.Text(key), e.Text(val))
	}
	// Output:
	// src = 10.0.0.1
	// dst = 2.1.2.2
}

func ExampleEvent_MarshalText() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|Security|ThreatManager|1.0|100|Alert|5|src=10.0.0.1`))
	if err != nil {
		panic(err)
	}
	b, err := e.MarshalText()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
	// Output:
	// CEF:0|Security|ThreatManager|1.0|100|Alert|5|src=10.0.0.1
}

func ExampleEvent_AppendText() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|Security|ThreatManager|1.0|100|Alert|5|src=10.0.0.1`))
	if err != nil {
		panic(err)
	}

	// AppendText with a pre-allocated buffer avoids allocations.
	buf := make([]byte, 0, 256)
	buf, err = e.AppendText(buf)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(buf))
	// Output:
	// CEF:0|Security|ThreatManager|1.0|100|Alert|5|src=10.0.0.1
}

func ExampleEvent_Clone() {
	p := cef.NewParser()
	e, err := p.Parse([]byte(`CEF:0|V|P|1|100|N|5|src=10.0.0.1`))
	if err != nil {
		panic(err)
	}

	// Clone creates an independent deep copy.
	saved := e.Clone()

	// Parsing again overwrites the Parser's internal Event...
	if _, err := p.Parse([]byte(`CEF:0|Other|X|2|200|Y|8|dst=2.2.2.2`)); err != nil {
		panic(err)
	}

	// ...but the clone is unaffected.
	fmt.Println("Vendor:", saved.Text(saved.Vendor))
	if src, ok := saved.ExtString("src"); ok {
		fmt.Println("Source:", saved.Text(src))
	}
	// Output:
	// Vendor: V
	// Source: 10.0.0.1
}

func ExampleEvent_UnmarshalText() {
	var e cef.Event
	err := e.UnmarshalText([]byte(`CEF:0|Cisco|ASA|9.16|430003|ACL deny|7|src=10.0.0.1`))
	if err != nil {
		panic(err)
	}
	fmt.Println("Vendor:", e.Text(e.Vendor))
	level, _ := e.SeverityLevel()
	fmt.Println("Severity:", level)
	// Output:
	// Vendor: Cisco
	// Severity: High
}

func ExampleUnescapeHeader() {
	raw := []byte(`detected a \| in message`)
	fmt.Println(string(cef.UnescapeHeader(raw, nil)))
	// Output:
	// detected a | in message
}

func ExampleUnescapeExtValue() {
	raw := []byte(`C:\\Windows\\System32`)
	fmt.Println(string(cef.UnescapeExtValue(raw, nil)))
	// Output:
	// C:\Windows\System32
}
