package cef

import "testing"

// fuzzCorpus is the seed corpus for fuzzing — covers valid, vendor, edge-case,
// and malformed inputs.
var fuzzCorpus = []string{
	`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|`,
	`CEF:0|Security|ThreatManager|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2`,
	`CEF:0|security|threatmanager|1.0|100|detected a \| in message|10|src=10.0.0.1`,
	`CEF:0|V|P|1|100|N|5|msg=hello\=world src=1.2.3.4`,
	`CEF:0|V|P|1|100|N|5|filePath=C:\\Windows\\System32 src=10.0.0.1`,
	`CEF:0|V|P|1|100|N|5|msg=first line\nsecond line src=1.2.3.4`,
	`CEF:0||||||5|`,
	`CEF:0|V|P|1|100|N|Unknown|`,
	`CEF:0|V|P|1|100|N|Very-High|`,
	`CEF:1|Vendor|Product|1.0|100|Name|5|`,
	`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|CiscoCVAlertType=Intrusion`,
	`CEF:0|Check Point|NGFW|R81.20|25000|Accept|3|src=10.0.0.100 cp_severity=Low`,
	`CEF:0|Palo Alto Networks|PAN-OS|11.0|TRAFFIC|end|3|PanOSRuleUUID=abc-123`,
	`CEF:0|V|P|1|100|N|5|msg=hello world   `,
	`CEF:0|V|P|1|100|N|5|msg=hello   src=1.2.3.4`,
	`CEF:0|vendor|product|1.0|100|name with \\|5|`,
	``, `NOT CEF`, `CEF:`, `CEF:0`, `CEF:0|`, `CEF:0|Vendor`,
	`CEF:abc|V|P|1|100|N|5|`, `NOTCEF:0|a|b|c|d|e|5|`,
	`CEF:0|Cisco|ASA|9.16|430003|ACL deny|7|src=192.168.1.1 act=Deny`,
	`CEF:0|Forcepoint|NGFW|6.10|100100|Connection Allowed|2|in=1234 out=5678`,
	`CEF:0|Fortinet|FortiGate|7.2.0|0000000013|forward traffic|5|act=accept`,
	`CEF:0|McAfee|ePO|5.10|THREAT_EVENT|Threat Detected|8|act=blocked`,
	`CEF:0|NXLog|Agent|5.6|1000|Windows Event|3|shost=DC01`,
	`CEF:2|V|P|1|100|N|5|src=1.2.3.4`, `CEF:99|V|P|1|100|N|5|`,
	`CEF:0|V|P|1|SIG=100|N|5|src=1.2.3.4`,
	`CEF:0|V|P|1|100|N|Low|`, `CEF:0|V|P|1|100|N|Medium|`,
	`CEF:0|V|P|1|100|N|High|`, `CEF:0|V|P|1|100|N|0|`, `CEF:0|V|P|1|100|N|10|`,
	`CEF:0|V|P|1|100|日本語|5|msg=こんにちは`,
	`CEF:0|V|P|1|100|N|5|rt=1234567890000`,
	`CEF:0|V|P|1|100|N|5|msg=contains | pipe src=1.2.3.4`,
	`CEF:0|V|P|1|100|N|5|msg=test\\\=value src=1.2.3.4`,
	`CEF:0|V|P|1|100|N|5|a.b=1 c-d=2 e_f=3 g[0]=4`,
	`CEF:0|only two fields`, `CEF:0|V|P|1|100|N`, `C`, `CE`, `CEF`,
}

// exerciseEvent exercises all accessors on a parsed event to detect panics.
func exerciseEvent(e *Event) {
	_ = e.Valid()
	_, _ = e.SeverityNum()
	_, _ = e.SeverityLevel()
	_ = e.String()
	if !e.Vendor.IsEmpty() {
		_ = e.Bytes(e.Vendor)
		_ = e.Text(e.Vendor)
	}
	if !e.Product.IsEmpty() {
		_ = e.Text(e.Product)
	}
	for i := range e.ExtCount {
		p, _ := e.ExtAt(i)
		_ = e.Bytes(p.Key)
		_ = e.Bytes(p.Value)
	}
	_, _ = e.ExtString("src")
	_, _ = e.Ext([]byte("dst"))
	// Test out-of-range Span.
	_ = e.Bytes(Span{Start: 0, End: 999999})
	_ = e.Text(Span{Start: 10, End: 5})
	// Exercise Clone.
	c := e.Clone()
	_ = c.Valid()
	_ = c.String()
	// Exercise MarshalText.
	if b, err := e.MarshalText(); err == nil && b != nil {
		_ = string(b)
	}
	// Exercise MarshalText on clone.
	if b, err := c.MarshalText(); err == nil && b != nil {
		_ = string(b)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzCorpus {
		f.Add([]byte(s))
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Normal mode: must not panic.
		m := NewParser()
		e, err := m.Parse(data)
		if err == nil && e != nil {
			exerciseEvent(e)
		}

		// Best-effort mode: must not panic.
		m2 := NewParser(WithBestEffort())
		e2, errBE := m2.Parse(data)
		_ = errBE // best-effort: errors expected for fuzz input
		if e2 != nil {
			exerciseEvent(e2)
		}
	})
}
