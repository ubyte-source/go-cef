# Test data provenance

Every directory and file under `testdata`, with its source, its licence and how it is made. The
repository is under the Apache License 2.0; each section below names the licence of its files.

No line comes from the CEF corpus of Elastic Beats, which is under the Elastic License 2.0: no line
of the vendor and grammar files equals, holds, or restates with other values an input of the
Beats tests at tag v9.5.5 (commit b80bf8464fba72f582cefed91dd72909eb7116db), the files
`testdata/samples.log`, `cef/cef_test.go`, `cef/types_test.go` and `decode_cef_test.go` of
`x-pack/filebeat/processors/decode_cef`. Several inputs of `logstash-cases.json` also appear,
verbatim or nearly, in the Beats tests; that file takes them from the Apache-2.0 Logstash spec
named below.

## Vendor and grammar corpus

Source: this repository. Licence: Apache-2.0, but for the lines of the standard that the table
names, which are quoted from it to test against it. Each file holds events in the CEF output of the
products or the grammar case the table names, one event a line.
`TestEventParseMatchesTheReferenceOnTheCorpus` parses every line of every `.cef` file and compares
the result with the reference parser `refParse` of `doc_test.go`, and
`TestEventAppendTextRoundTrips` writes each event that Parse reads as text and parses it back.

| file | events | content |
|---|---|---|
| `arcsight/spec_example.cef` | 15 | ArcSight ESM, Logger and SmartConnector events; lines 1-2 are the standard's version 0 and pipe examples, line 1 with the product written `ThreatManager` |
| `aws/guardduty.cef` | 12 | AWS GuardDuty, CloudTrail, WAF and SecurityHub |
| `barracuda/waas_ms.cef` | 10 | Barracuda WAAS |
| `barracuda/waf.cef` | 12 | Barracuda WAAS |
| `bitdefender/gravityzone.cef` | 10 | Bitdefender GravityZone |
| `carbonblack/edr.cef` | 12 | Carbon Black CB EDR and CB Cloud |
| `cef1_samples/mixed.cef` | 68 | version 1 events of several vendors; line 1 is the standard's version 1 example with the product written `ThreatManager` |
| `checkpoint/ngfw.cef` | 16 | Check Point NGFW, SmartEvent, URL Filtering, Threat Emulation, IPS, Identity Awareness, DLP, Anti-Virus and Anti-Bot |
| `cisco_cybervision/alert.cef` | 19 | Cisco ASA, Firepower, Cyber Vision, ISE, ESA, WSA, Umbrella, Secure Endpoint and Duo |
| `crowdstrike/falcon.cef` | 15 | CrowdStrike FalconHost |
| `cyberark/pta.cef` | 12 | CyberArk PTA, Vault and EPM |
| `darktrace/detect.cef` | 12 | Darktrace Enterprise and Antigena |
| `edge_cases/edge.cef` | 51 | grammar edges: empty fields, escapes, spaces, unusual keys and values |
| `edge_cases/edge_cases.cef` | 2 | spaces between `CEF:` and the version |
| `f5/bigip.cef` | 12 | F5 BIG-IP ASM, LTM, AFM and APM |
| `fireeye/hx.cef` | 12 | FireEye HX, NX, EX and AX |
| `forcepoint/ngfw.cef` | 14 | Forcepoint NGFW, Web Security, Insider Threat, Email Security, DLP and CASB |
| `fortinet/fortigate.cef` | 19 | Fortinet FortiGate, FortiSandbox, FortiMail and FortiAnalyzer |
| `fortiweb/waf.cef` | 6 | Fortinet FortiWeb, with empty vendor and product fields |
| `illumio/pce.cef` | 2 | Illumio PCE |
| `imperva/waf.cef` | 16 | Imperva SecureSphere, Incapsula and Data Security |
| `juniper/srx.cef` | 12 | Juniper SRX, Mist and ATP |
| `malformed/broken.cef` | 32 | malformed and truncated lines |
| `mcafee/epo.cef` | 15 | McAfee ePO, NSM, MVISION and DLP |
| `microsoft_ata/alerts.cef` | 12 | Microsoft ATA and Defender for Identity |
| `nxlog/windows.cef` | 18 | Windows events as NXLog writes them |
| `paloalto/traffic.cef` | 19 | Palo Alto Networks PAN-OS, Cortex XDR and Prisma Cloud |
| `proofpoint/tap.cef` | 11 | Proofpoint TAP, TRAP and CASB |
| `qualys/vmdr.cef` | 10 | Qualys VMDR, WAS, PC, EDR and CS |
| `radiflow/isid.cef` | 5 | Radiflow iSID |
| `rapid7/idr.cef` | 11 | Rapid7 InsightIDR, InsightVM and InsightConnect |
| `sentinelone/singularity.cef` | 15 | SentinelOne Singularity |
| `sophos/xg.cef` | 14 | Sophos XG Firewall, Intercept X and Central |
| `splunk/uba.cef` | 15 | Splunk UBA, ES and SOAR |
| `symantec/sep.cef` | 12 | Symantec Endpoint Protection, Threat Isolation, DLP and CloudSOC |
| `trendmicro/deepsecurity.cef` | 15 | Trend Micro Deep Security, Cloud One, Apex One and Vision One |
| `vectra/cognito.cef` | 12 | Vectra Cognito Detect and Cognito Stream |
| `votiro/cloud.cef` | 15 | Votiro Cloud |
| `watchguard/firebox.cef` | 11 | WatchGuard Firebox |
| `withsecure/edr.cef` | 15 | F-Secure Computer Protection Premium and EDR |
| `zscaler/zia.cef` | 12 | Zscaler NSSWeblog, NSSFirewalllog, NSSDNSlog and ZPA |

## Conformance cases

`standard-examples.json`. Source: "Implementing ArcSight Common Event Format (CEF)", Version 27
(OpenText, SmartConnector 24.3, July 2024), and for the cases named `Microsoft Learn` the two pages
below. The file opens with the seven examples of pages 7-9. Each line but the filePath one is the
event as the standard prints it, without its syslog prefix, which is `Sep 29 08:26:10 host ` for the
version 1 example and `Sep 19 08:26:10 host ` for the others. The filePath example, of spaces in a
value, prints only its pair, so its line takes the header of the first example. The six examples
that print a prefix follow with it, refused with `ErrPrefix`.

Each case named `v27 p.<page>: <rule>` tests the rule that page of Version 27 states, and the cases
hold one line or more for each rule of the event line that a reader or a writer follows: the prefix
and the version, the seven pipes, the header and extension escapes, the bytes of a key, the spaces
between and inside pairs, empty, multi-line and UTF-8 values, each Severity form of page 7, custom
keys and their labels, and every key of the dictionary of pages 10-42, each with its full name as
its value. A line the standard does not admit gets the fault or the reading that README states. The
expected fields of every line follow the standard's text and decoding rules. Left out, as no JSON
string holds them: bytes that are not UTF-8, which Parse passes through. The data types, lengths and
date formats of the dictionary give a value a meaning that Parse does not read, so no case tests
them. Licence: the example lines and the keys and full names of the dictionary are quoted from the
standard to test against it; the other lines and the expected fields are Apache-2.0.

The cases named `Microsoft Learn Sentinel` take the two test messages of "Ingest syslog and CEF
messages to Microsoft Sentinel - AMA": lines 429 and 435 of
`articles/sentinel/connect-cef-syslog-ama.md` in MicrosoftDocs/azure-docs, commit
2042480695dd5325557820cfb5c6fb4629224f42 (the file's SHA-256 is
622cb186f1d691375103e2b5725538dba00add38e28ef1b92d76eb76195a8fde). Licence: the repository puts its
text under CC BY 4.0 and its code blocks, which hold the messages, under the MIT License, "Copyright
(c) Microsoft Corporation". The first case is the text between the quotes of the `echo` command,
`$common` as printed; the second is that text without its syslog priority `<164>`; the third is the
quoted message of the `logger` command, which `logger --rfc3164 -t CEF` writes after its tag `CEF:`
and a space.

The cases named `Microsoft Learn ATA` take two sample logs of "ATA SIEM log reference": lines 89 and
154 of `ATADocs/cef-format-sa.md` in MicrosoftDocs/ATADocs, commit
dd50b632a69d95b4458ddbbe9be710ccec6a14a7 (the file's SHA-256 is
8469a05046360edcb2c0630082442dd98de46161dc5b1e80d3b921b3b11d5840). Licence: CC BY 4.0, the licence
Microsoft gives the repository's text. The first case is line 89 as printed, with its syslog header;
the second is that line from `CEF:`; the third is line 154 from `CEF:`.

Neither page states the fields of its lines, so the expected fields of these cases follow the
standard's rules, and the table gives what the page does with a line that Parse refuses, or what it
means by a value read otherwise here.

- The Sentinel page: https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama
- The Sentinel file: https://github.com/MicrosoftDocs/azure-docs/blob/2042480695dd5325557820cfb5c6fb4629224f42/articles/sentinel/connect-cef-syslog-ama.md
- CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
- The MIT notice: https://github.com/MicrosoftDocs/azure-docs/blob/2042480695dd5325557820cfb5c6fb4629224f42/LICENSE-CODE
- The ATA page: https://learn.microsoft.com/en-us/previous-versions/advanced-threat-analytics/cef-format-sa
- The ATA file: https://github.com/MicrosoftDocs/ATADocs/blob/dd50b632a69d95b4458ddbbe9be710ccec6a14a7/ATADocs/cef-format-sa.md

| case | expected here | Microsoft Learn | rule |
|---|---|---|---|
| Sentinel: the test message with its priority | refused, `ErrPrefix` | sent to a syslog port, whose daemon reads `<164>` as the priority | a syslog header is refused; the caller strips it |
| Sentinel: the logger message, which lacks a field | refused, `ErrIncompleteHeader`, its six fields kept | a demo message | the header ends at its seventh pipe, and the message has six |
| ATA: an RFC 5424 syslog header before CEF: | refused, `ErrPrefix` | a sample log as the SIEM receives it | as for the first row |
| ATA: a group change alert, `\:` kept | `cs1` `https\://192.168.0.220/suspiciousActivity/5c113d028ca1ec1250ca0491` | the URL that `cs1Label=url` names, `https://192.168.0.220/...` | `\:` is no escape of Version 27, so its backslash stays |
| ATA: a monitoring alert, colons and spaces in the last value | `cs1` `https\://192.168.0.220/monitoring` | `https://192.168.0.220/monitoring` | as for the row above |

`logstash-cases.json`. Source: the decode cases of `spec/codecs/cef_spec.rb` in
logstash-plugins/logstash-codec-cef, tag v6.2.8, commit 307aec4c953dcbb7c4bdb67aafe868c41b810d33
(the file's SHA-256 is e59d93955c7bfc0be6bbf0f995b17d5a7b50554725b3b444676c0071bf1022cb). Licence:
Apache-2.0, "Elasticsearch, Copyright 2012-2015 Elasticsearch" as the project's NOTICE.TXT states.
Each input is the Ruby literal of its case, byte for byte, and each case is named by the line of its
`it` in `cef_spec.rb`. Where Logstash's rule agrees with the rule Parse documents, the expected
fields are the values the spec asserts; where it differs, they are the split of `refParse` decoded
by the standard's escape rules, and the table below gives Logstash's value. Fields a case does not
assert are read the same way. The keys are the CEF keys as the line writes them: Logstash stores
each under its long name (`sourceAddress`) or its ECS field (`[source][ip]`), and `ad.field[0]` as
`[ad.field][0]`. The two encodings of the UTF-8 case (lines 979-993) give the same bytes, so they
are one case.

Left out, as tests of Logstash options only: the delimiter cases (lines 492, 513 and 522), the
timestamps of the ECS mode (lines 714 and 734), `raw_data_field` (line 1014), and the encoder,
sanitizer and severity contexts (lines 16-377 and 1038-1089). Left out too: the Shift_JIS case
(line 1002), whose line is not UTF-8 and so is no JSON string.

| case | expected here | Logstash | rule |
|---|---|---|---|
| 549, 562 | refused, `ErrPrefix` | refused: 0 and 4 of 7 header fields | an event starts with `CEF:` |
| 575 | refused, `ErrExtKey`, header kept | refused: keyless value | the extension is key=value pairs |
| 597 | one event, `src` holding the four lines after it | refused: unescaped newlines | Parse reads one event; the caller splits lines |
| 843 | `src` `10.0.0.192 `, `dst` `12.121.122.82 ` | `10.0.0.192`, `12.121.122.82` | the spaces before a key, except the separator, belong to the previous value |
| 863 | `dst` `12.121.122.82 ` | `12.121.122.82` | as for 843 |
| 874, 888, 902 | `ad.Authentification` `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 ad.Error_,Code=3221225578` | `ad.Authentification` `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` and `ad.Error_,Code` `3221225578` | a key is A-Z, a-z, 0-9, `.`, `_`, `-`, `[` and `]`, so `ad.Error_,Code=` starts no pair |
| 943, 951, 959 | refused, `ErrPrefix` | the event, with `Syslogdate Sysloghost` as its syslog header | a syslog prefix is refused; the caller strips it |

## Format of the conformance files

A conformance file is a JSON array of cases. Each case has a `name`, the failure message of a test
names it; a `line`, the input Parse reads; a `version`; a `header`, the six fields Device Vendor,
Device Product, Device Version, Device Event Class ID, Name and Severity decoded by UnescapeHeader;
`pairs`, each key with its value decoded by UnescapeExtValue, in order, absent for an event without
pairs; and a `fault`, the sentinel Parse returns, such as `ErrPrefix`, absent when Parse returns
nil. A case may also hold a `severityLevel`: the `level`, `number` and `ok` that SeverityLevel gives
for its Severity field. `TestEventParseReadsTheStandardExamples` and
`TestEventParseReadsTheLogstashCases` of `parse_test.go` parse each line with `MaxExtensions` and
compare the version, the decoded header fields, the pairs and the error with the case.
