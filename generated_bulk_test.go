package cef

import (
	"fmt"
	"strings"
	"testing"
)

// TestGeneratedBulkCEF generates and parses thousands of diverse CEF events.
func TestGeneratedBulkCEF(t *testing.T) {
	m := NewParser()
	total := 2000
	parsed := 0
	for i := range total {
		line := buildBulkCEFLine(i)
		e, err := m.Parse([]byte(line))
		if err != nil {
			t.Errorf("event %d: parse error: %v\n  line: %s", i, err, truncate(line, 150))
			continue
		}
		if e == nil || !e.Valid() {
			t.Errorf("event %d: nil or invalid\n  line: %s", i, truncate(line, 150))
			continue
		}
		parsed++
	}
	t.Logf("Successfully parsed %d/%d generated CEF events", parsed, total)
	if parsed < total*95/100 {
		t.Errorf("Expected at least 95%% parse rate, got %d/%d", parsed, total)
	}
}

func buildBulkCEFLine(i int) string {
	v := bulkVendors[i%len(bulkVendors)]
	cefVer := bulkCEFVersions[i%len(bulkCEFVersions)]
	sigID := bulkSigIDs[(i*7)%len(bulkSigIDs)]
	name := bulkNames[(i*13)%len(bulkNames)]
	sev := bulkSeverities[(i*3)%len(bulkSeverities)]

	exts := buildBulkExtensions(i)

	if len(exts) > 0 {
		return fmt.Sprintf("CEF:%d|%s|%s|%s|%s|%s|%s|%s",
			cefVer, v.vendor, v.product, v.version,
			sigID, name, sev, strings.Join(exts, " "))
	}
	return fmt.Sprintf("CEF:%d|%s|%s|%s|%s|%s|%s|",
		cefVer, v.vendor, v.product, v.version,
		sigID, name, sev)
}

func buildBulkExtensions(i int) []string {
	// Every ~20th event has no extensions.
	if i%20 == 0 {
		return nil
	}

	var exts []string
	exts = append(exts, "src="+bulkSrcIPs[(i*11)%len(bulkSrcIPs)])

	if i%5 != 0 {
		exts = append(exts, "dst="+bulkDstIPs[(i*17)%len(bulkDstIPs)])
	}
	if i%3 != 0 {
		exts = append(exts, fmt.Sprintf("spt=%d", 1024+(i*37)%64000))
		exts = append(exts, fmt.Sprintf("dpt=%d", (i*53)%65535))
	}
	if i%3 != 1 {
		exts = append(exts, "proto="+bulkProtos[(i*19)%len(bulkProtos)])
	}
	if i%5 != 1 {
		exts = append(exts, "act="+bulkActions[(i*23)%len(bulkActions)])
	}
	if i%2 == 0 {
		exts = append(exts, "duser="+bulkUsers[(i*29)%len(bulkUsers)])
	}
	if i%3 == 0 {
		exts = append(exts, fmt.Sprintf("dhost=HOST%03d", i%100))
	}
	if i%4 == 0 {
		exts = append(exts, "deviceProcessName="+bulkProcesses[(i*31)%len(bulkProcesses)])
	}
	if i%5 == 0 {
		exts = append(exts, "fname="+bulkFnames[(i*41)%len(bulkFnames)])
	}
	if i%3 == 2 {
		v := bulkVendors[i%len(bulkVendors)]
		exts = append(exts, fmt.Sprintf("msg=%s event %d from %s %s",
			bulkNames[(i*13)%len(bulkNames)], i, v.vendor, v.product))
	}
	if i%4 == 1 {
		exts = append(exts, fmt.Sprintf("cs1=CustomValue%d cs1Label=CustomLabel%d", i%100, i%10))
	}
	if i%6 == 0 {
		exts = append(exts, fmt.Sprintf("cn1=%d cn1Label=Count", i%10000))
	}
	if i%7 == 0 {
		exts = append(exts, fmt.Sprintf("in=%d out=%d", (i*97)%1000000, (i*83)%1000000))
	}
	if i%4 == 3 {
		exts = append(exts, fmt.Sprintf("rt=%d", 1700000000000+int64(i*1000)))
	}
	return exts
}

type bulkVendor struct{ vendor, product, version string }

var bulkVendors = []bulkVendor{
	{"Security", "ThreatManager", "1.0"},
	{"ArcSight", "ESM", "7.6"},
	{"Check Point", "NGFW", "R81.20"},
	{"Palo Alto Networks", "PAN-OS", "11.0"},
	{"Fortinet", "FortiGate", "7.4.0"},
	{"CrowdStrike", "FalconHost", "1.0"},
	{"SentinelOne", "Singularity", "4.0"},
	{"Trend Micro", "Deep Security", "20.0"},
	{"McAfee", "ePO", "5.10"},
	{"Cisco", "Firepower", "7.2"},
	{"Cisco", "ASA", "9.16"},
	{"Symantec", "Endpoint Protection", "14.3"},
	{"Carbon Black", "CB Cloud", "3.0"},
	{"Sophos", "XG Firewall", "19.5"},
	{"Zscaler", "NSSWeblog", "6.0"},
	{"F5", "BIG-IP ASM", "16.1"},
	{"Juniper", "SRX", "21.4"},
	{"Imperva Inc.", "SecureSphere", "14.7"},
	{"FireEye", "HX", "5.0"},
	{"Microsoft", "ATA", "1.9.0.0"},
	{"Microsoft", "Windows", "10.0"},
	{"CyberArk", "PTA", "15.0"},
	{"Darktrace", "Enterprise", "6.0"},
	{"Vectra", "Cognito Detect", "7.0"},
	{"WatchGuard", "Firebox", "12.10"},
	{"Barracuda", "WAF", "12.0"},
	{"Proofpoint", "TAP", "2.0"},
	{"Qualys", "VMDR", "10.0"},
	{"Rapid7", "InsightIDR", "4.0"},
	{"AWS", "GuardDuty", "2.0"},
	{"Bitdefender", "GravityZone", "6.40"},
	{"Splunk", "ES", "7.3"},
	{"Forcepoint", "NGFW", "6.10"},
	{"Okta", "SSO", "2023.1"},
	{"Cloudflare", "WAF", "4.0"},
	{"Akamai", "Kona", "3.0"},
	{"IBM", "QRadar", "7.5"},
	{"LogRhythm", "SIEM", "7.10"},
	{"Elastic", "SIEM", "8.11"},
	{"Sumo Logic", "Cloud SIEM", "3.0"},
}

var bulkSigIDs = []string{
	"100", "200", "300", "4624", "4625", "4688", "4720",
	"THREAT", "TRAFFIC", "SYSTEM", "IPS001", "AV001", "FW001",
	"DLP001", "WAF001", "DNS001", "VPN001", "AUTH001", "SCAN001",
	"MALWARE", "EXPLOIT", "RECON", "LATERAL", "EXFIL", "C2",
	"1:2024217:3", "rule:50", "CVE-2021-44228", "BOT001",
	"PHISH001", "RANSOM001", "CRYPT001", "DDOS001", "BRUTEFORCE",
}

var bulkNames = []string{
	"Firewall Allow", "Firewall Deny", "Firewall Drop",
	"IPS Alert", "IPS Block", "Malware Detected",
	"Virus Found", "Trojan Detected", "Ransomware Blocked",
	"SQL Injection", "XSS Attempt", "Command Injection",
	"Directory Traversal", "Brute Force Attack",
	"Account Lockout", "Failed Login", "Successful Login",
	"Privilege Escalation", "Lateral Movement",
	"Data Exfiltration", "DNS Tunneling",
	"C2 Communication", "Port Scan", "DDoS Attack",
	"Phishing Email", "Spam Detected", "VPN Connected",
	"Certificate Error", "Policy Violation",
	"Vulnerability Detected", "Patch Missing",
	"Agent Connected", "Scan Complete",
	"Bot Detected", "Credential Theft",
	"Process Injection", "Fileless Attack",
	"Anomalous Connection", "Beaconing Activity",
	"Insider Threat", "Shadow IT",
}

var bulkSeverities = []string{
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
	"Low", "Medium", "High", "Very-High", "Unknown",
}

var bulkCEFVersions = []int{0, 0, 0, 0, 0, 0, 0, 1, 1, 1}

var bulkSrcIPs = []string{
	"10.0.0.1", "10.0.0.50", "10.0.0.100", "10.0.0.200",
	"172.16.0.5", "172.16.0.50", "172.16.0.100",
	"192.168.1.1", "192.168.1.50", "192.168.1.100",
	"203.0.113.5", "203.0.113.50", "203.0.113.100", "203.0.113.200",
	"198.51.100.10", "198.51.100.50", "198.51.100.100",
	"2001:db8::1", "2001:db8::50", "fe80::1",
}

var bulkDstIPs = []string{
	"10.0.0.5", "10.0.0.10", "10.0.0.200",
	"8.8.8.8", "8.8.4.4", "1.1.1.1",
	"172.217.14.110", "52.96.108.170", "151.101.1.69",
	"93.184.216.34", "198.51.100.20", "203.0.113.50",
	"2001:db8::2", "fe80::2",
}

var bulkProtos = []string{"TCP", "UDP", "ICMP", "ESP", "GRE"}
var bulkActions = []string{
	"allow", "deny", "drop", "block", "alert", "detect",
	"quarantine", "contain", "accept", "reject", "reset",
	"Allowed", "Blocked", "Dropped", "Alert", "Prevented",
}

var bulkUsers = []string{
	"admin", "jsmith", "root", "SYSTEM", "user01",
	"CORP\\\\admin", "CORP\\\\jsmith", "CORP\\\\analyst",
	"svc_account", "admin@corp.com", "user@example.com",
}

var bulkProcesses = []string{
	"powershell.exe", "cmd.exe", "rundll32.exe", "wscript.exe",
	"certutil.exe", "mimikatz.exe", "psexec.exe", "mshta.exe",
	"svchost.exe", "explorer.exe", "chrome.exe", "iexplore.exe",
}

var bulkFnames = []string{
	"malware.exe", "trojan.dll", "payload.pdf", "invoice.docm",
	"ransomware.bin", "exploit.html", "dropper.js", "backdoor.sys",
	"suspicious.zip", "zero_day.doc", "phish.eml", "cryptominer.exe",
}
