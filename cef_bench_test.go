package cef_test

import (
	"strings"
	"testing"

	cef "github.com/ubyte-source/go-cef"
)

func BenchmarkExtLookup(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.ExtString("msg")
	}
}

func BenchmarkExtLookupBytes(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
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
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.ExtAt(5) // "act"
	}
}

func BenchmarkExtLookupMiss(b *testing.B) {
	// Build input with many extensions so lookup scans all of them.
	parts := make([]string, 0, 50)
	for i := range 50 {
		k := string(rune('A'+i/26)) + string(rune('a'+i%26))
		parts = append(parts, k+"=v")
	}
	input := []byte(`CEF:0|V|P|1|100|N|5|` + strings.Join(parts, " "))
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.ExtString("nonexistent")
	}
}

func BenchmarkExtAll(b *testing.B) {
	input := []byte(
		`CEF:0|V|P|1|100|N|5|` +
			`src=10.0.0.1 dst=2.1.2.2 spt=1232 ` +
			`dpt=443 proto=TCP act=Deny msg=test message`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, v := range e.All() {
			_ = v
		}
	}
}

func BenchmarkClone(b *testing.B) {
	input := []byte(
		`CEF:0|Cisco|Cyber Vision|4.4.0|CiscoCVAlert|Alert|8|` +
			`CiscoCVAlertType=Intrusion src=192.168.1.100 dst=192.168.1.200`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		_ = e.Clone()
	}
}

func BenchmarkCloneCompact(b *testing.B) {
	padding := strings.Repeat("x", 1500)
	input := []byte(`CEF:0|V|P|1|100|` + padding + `|5|src=1.2.3.4`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
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
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
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
		if err := e.UnmarshalText(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalText(b *testing.B) {
	input := []byte(`CEF:0|Cisco|CyberVision|4.0|100|Alert|5|src=10.0.0.1 dst=2.1.2.2`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := e.MarshalText(); err != nil {
			b.Fatal(err)
		}
	}
}
