package cef_test

import (
	"testing"

	cef "github.com/ubyte-source/go-cef"
)

func BenchmarkSeverityNum(b *testing.B) {
	input := []byte(`CEF:0|V|P|1|100|N|8|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.SeverityNum()
	}
}

func BenchmarkSeverityNumNamed(b *testing.B) {
	input := []byte(`CEF:0|V|P|1|100|N|Low|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.SeverityNum()
	}
}

func BenchmarkSeverityLevel(b *testing.B) {
	input := []byte(`CEF:0|V|P|1|100|N|Very-High|`)
	m := cef.NewParser()
	e, err := m.Parse(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = e.SeverityLevel()
	}
}
