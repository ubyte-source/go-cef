package cef

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTestdataVendorSamples reads all .cef files from testdata/ vendor
// directories and ensures every non-empty line starting with "CEF:" parses
// without error. This is a data-driven integration test covering 35+ vendors.
func TestTestdataVendorSamples(t *testing.T) {
	vendors := []string{
		"arcsight", "cisco_cybervision", "checkpoint",
		"paloalto", "forcepoint", "imperva", "nxlog",
		"trendmicro", "fortinet", "mcafee",
		"crowdstrike", "sentinelone", "splunk",
		"fireeye", "microsoft_ata", "cyberark",
		"symantec", "carbonblack", "sophos",
		"zscaler", "f5", "juniper",
		"watchguard", "barracuda", "proofpoint",
		"qualys", "rapid7", "aws",
		"bitdefender", "darktrace", "vectra",
		"cef1_samples",
		// Microsoft Azure Sentinel CEF samples.
		"citrix", "illumio", "votiro",
		"fortiweb", "withsecure", "radiflow",
	}
	m := NewParser()

	for _, vendor := range vendors {
		dir := filepath.Join("testdata", vendor)
		files, err := filepath.Glob(filepath.Join(dir, "*.cef"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		if len(files) == 0 {
			t.Errorf("no .cef files found in %s", dir)
			continue
		}
		for _, file := range files {
			name := filepath.Join(vendor, filepath.Base(file))
			t.Run(name, func(t *testing.T) {
				assertVendorFile(t, m, file)
			})
		}
	}
}

// assertVendorFile parses each CEF line in the file and asserts validity.
func assertVendorFile(t *testing.T, m *Parser, file string) {
	t.Helper()
	lines := readLines(t, file)
	for i, line := range lines {
		if line == "" || !strings.HasPrefix(line, "CEF:") {
			continue
		}
		e, err := m.Parse([]byte(line))
		if err != nil {
			t.Errorf("line %d: parse error: %v\n  input: %s",
				i+1, err, truncate(line, 120))
			continue
		}
		if !e.Valid() {
			t.Errorf("line %d: message not valid\n  input: %s",
				i+1, truncate(line, 120))
		}
		// Ensure header fields are accessible.
		_ = e.Bytes(e.Vendor)
		_ = e.Bytes(e.Product)
		_ = e.Text(e.Name)
		_, _ = e.SeverityNum()
		// Ensure all extensions are accessible.
		for j := range e.ExtCount {
			_ = e.Bytes(e.exts[j].Key)
			_ = e.Bytes(e.exts[j].Value)
		}
	}
}

// TestTestdataEdgeCases reads edge_cases/*.cef and verifies parsing succeeds.
func TestTestdataEdgeCases(t *testing.T) {
	m := NewParser()
	files, err := filepath.Glob("testdata/edge_cases/*.cef")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			lines := readLines(t, file)
			for i, line := range lines {
				if line == "" || !strings.HasPrefix(line, "CEF:") {
					continue
				}
				e, err := m.Parse([]byte(line))
				if err != nil {
					t.Errorf("line %d: unexpected error: %v\n  input: %s",
						i+1, err, truncate(line, 120))
					continue
				}
				if !e.Valid() {
					t.Errorf("line %d: message not valid", i+1)
				}
			}
		})
	}
}

// TestTestdataMalformed reads malformed/*.cef with BestEffort and verifies
// no panics occur and partial results are returned.
func TestTestdataMalformed(t *testing.T) {
	m := NewParser(WithBestEffort())
	files, err := filepath.Glob("testdata/malformed/*.cef")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			lines := readLines(t, file)
			for i, line := range lines {
				if line == "" {
					continue
				}
				e, parseErr := m.Parse([]byte(line))
				if parseErr != nil && e == nil {
					t.Errorf("line %d: expected non-nil message in BestEffort mode",
						i+1)
					continue
				}
				if e == nil {
					t.Errorf("line %d: expected non-nil message in BestEffort mode",
						i+1)
				}
			}
		})
	}
}

// readLines reads all lines from a file. Uses filepath.Clean to satisfy gosec.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	cleaned := filepath.Clean(path)
	f, err := os.Open(cleaned)
	if err != nil {
		t.Fatalf("open %s: %v", cleaned, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close %s: %v", cleaned, cerr)
		}
	}()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", cleaned, err)
	}
	return lines
}

// truncate shortens a string for display in error messages.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
