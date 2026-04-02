# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in go-cef, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Use GitHub's private vulnerability reporting feature, or email the maintainers directly.
3. Include: description, steps to reproduce, and impact assessment.
4. We will acknowledge receipt within 48 hours and provide a fix timeline.

## Scope

go-cef is a parser library. Security concerns include:

- Denial of service via crafted input (e.g., excessive memory or CPU usage).
- Panics or crashes on adversarial input.
- Incorrect parsing that could lead to security bypass in downstream systems.

The library is fuzz-tested continuously with Go's built-in fuzzer.

## Known Limits

The parser enforces the following bounds to prevent resource exhaustion:

| Parameter | Limit | Constant |
|-----------|-------|----------|
| Maximum extensions per event | 64 | `MaxExtensions` |
| Maximum extension key length | 63 bytes | `maxKeyLen` |
| Maximum `=` scanned per value | 256 | `maxEqualsScanned` |
| Maximum input size | 4 GiB (`math.MaxUint32`) | — |

Inputs exceeding these limits are rejected with the appropriate sentinel error.
