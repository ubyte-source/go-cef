package cef_test

import (
	"strings"
	"testing"

	cef "github.com/ubyte-source/go-cef"
)

func BenchmarkParseMinimal(b *testing.B) {
	input := []byte(`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseCiscoCyberVision(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion CiscoCVSeverity=critical ` +
			`src=192.168.1.100 dst=192.168.1.200 ` +
			`msg=Suspicious network activity detected on OT segment`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseCiscoASA(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|ASA|9.16|430003|ACL deny|7|` +
			`src=192.168.1.1 dst=10.0.0.1 spt=12345 dpt=443 ` +
			`proto=TCP act=Deny cs1=outside cs1Label=Interface ` +
			`msg=Denied TCP connection`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseCheckPointHeavy(b *testing.B) {
	input := []byte(
		`CEF:0|Check Point|NGFW|R81.20|25000|Accept|3|` +
			`src=10.0.0.100 dst=8.8.8.8 spt=54321 dpt=53 ` +
			`proto=UDP act=Accept cp_severity=Low ` +
			`cp_logid=12345678 cp_product=Firewall ` +
			`cp_origin=10.0.0.1 cp_rule=100 ` +
			`cp_rule_name=DNS_Allow cp_chain_position=1 ` +
			`cp_interface=eth0 cp_segment=internal ` +
			`cp_src_zone=LAN cp_dst_zone=WAN`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParsePaloAlto(b *testing.B) {
	input := []byte(
		`CEF:0|Palo Alto Networks|PAN-OS|11.0|TRAFFIC|end|3|` +
			`src=10.0.0.1 dst=172.16.0.1 spt=45678 dpt=80 ` +
			`proto=TCP act=allow PanOSRuleUUID=abc-123 ` +
			`PanOSSourceZone=trust PanOSDestinationZone=untrust`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseWithEscaping(b *testing.B) {
	input := []byte(
		`CEF:0|security|threatmanager|1.0|100|` +
			`detected a \| in message|10|` +
			`src=10.0.0.1 msg=test\=value\nwith escapes ` +
			`act=blocked a | dst=1.1.1.1`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseHeaderOnly(b *testing.B) {
	input := []byte(`CEF:0|Vendor|Product|1.0|100|Event Name|5`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkExtLookup(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.ExtString("msg")
	}
}

func BenchmarkSeverityNum(b *testing.B) {
	input := []byte(`CEF:0|V|P|1|100|N|8|`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.SeverityNum()
	}
}

func BenchmarkParseParallel(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion CiscoCVSeverity=critical ` +
			`src=192.168.1.100 dst=192.168.1.200 ` +
			`msg=Suspicious activity`)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		m := cef.NewParser()
		for pb.Next() {
			_, _ = m.Parse(input)
		}
	})
}

func BenchmarkParseBestEffort(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion src=192.168.1.100`)
	m := cef.NewParser(cef.WithBestEffort())
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkSeverityNumNamed(b *testing.B) {
	input := []byte(`CEF:0|V|P|1|100|N|Low|`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.SeverityNum()
	}
}

func BenchmarkSeverityLevel(b *testing.B) {
	input := []byte(`CEF:0|V|P|1|100|N|Very-High|`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.SeverityLevel()
	}
}

func BenchmarkExtLookupBytes(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	key := []byte("msg")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.Ext(key)
	}
}

func BenchmarkExtAt(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.ExtAt(5) // "act"
	}
}

func BenchmarkExtLookupMiss(b *testing.B) {
	// Build input with many extensions so lookup scans all of them.
	parts := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		k := string(rune('A'+i/26)) + string(rune('a'+i%26))
		parts = append(parts, k+"=v")
	}
	input := []byte(`CEF:0|V|P|1|100|N|5|` + strings.Join(parts, " "))
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.ExtString("nonexistent")
	}
}

func BenchmarkParseMalformedPrefix(b *testing.B) {
	input := []byte(`NOTCEF:0|a|b|c|d|e|5|src=1.2.3.4`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseMalformedTruncated(b *testing.B) {
	input := []byte(`CEF:0|Vendor|Product`)
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseMalformedBestEffort(b *testing.B) {
	input := []byte(`CEF:0|Vendor|Product|1.0|100|Name`)
	m := cef.NewParser(cef.WithBestEffort())
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkClone(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion src=192.168.1.100 dst=192.168.1.200`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_ = e.Clone()
	}
}

func BenchmarkParse64Extensions(b *testing.B) {
	parts := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		k := string(rune('A'+i/26)) + string(rune('a'+i%26))
		parts = append(parts, k+"=value"+string(rune('0'+i%10)))
	}
	input := []byte(`CEF:0|V|P|1|100|N|5|` + strings.Join(parts, " "))
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkExtAll(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, v := range e.All() {
			_ = v
		}
	}
}

func BenchmarkCloneCompact(b *testing.B) {
	padding := strings.Repeat("x", 1500)
	input := []byte(`CEF:0|V|P|1|100|` + padding + `|5|src=1.2.3.4`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_ = e.Clone()
	}
}

func BenchmarkCloneTo(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion src=192.168.1.100 dst=192.168.1.200`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	dst := new(cef.Event)
	e.CloneTo(dst) // warmup
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for b.Loop() {
		e.CloneTo(dst)
	}
}

func BenchmarkUnmarshalText(b *testing.B) {
	input := []byte(`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|src=10.0.0.1 dst=2.1.2.2`)
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		var e cef.Event
		_ = e.UnmarshalText(input)
	}
}

func BenchmarkMarshalText(b *testing.B) {
	input := []byte(`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|src=10.0.0.1 dst=2.1.2.2`)
	m := cef.NewParser()
	e, _ := m.Parse(input)
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.MarshalText()
	}
}

func BenchmarkParseAdversarialEquals(b *testing.B) {
	// Extension value with many non-key '=' chars — stresses findValueEnd.
	val := strings.Repeat("@x=1 ", 500)
	input := []byte("CEF:0|V|P|1|100|N|5|msg=" + val + "src=1.2.3.4")
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseAdversarialBackslashes(b *testing.B) {
	// Long backslash run before '=' — stresses isEscapedAt.
	bs := strings.Repeat(`\`, 4000)
	input := []byte("CEF:0|V|P|1|100|N|5|msg=" + bs + "= src=1.2.3.4")
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}

func BenchmarkParseAdversarialEscapedPipes(b *testing.B) {
	// Header field with many escaped pipes — stresses escaped-pipe detection.
	val := strings.Repeat(`\|`, 500)
	input := []byte("CEF:0|V|P|1|100|" + val + "|5|src=1.2.3.4")
	m := cef.NewParser()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_, _ = m.Parse(input)
	}
}
