# security-headers-analyzer

[![CI](https://github.com/mrsadik2175/security-headers-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/mrsadik2175/security-headers-analyzer/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)](#)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A command-line tool that analyzes the HTTP security headers of any given URL,
identifies missing or misconfigured headers, scores the associated risk, and
generates a clear, actionable report - with SSRF protection built in from
the ground up.

Inspired by tools like [securityheaders.com](https://securityheaders.com) and
the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
built as a self-contained AppSec learning + portfolio project.

## Status

✅ **v1.0.0 — Production release.** See [CHANGELOG.md](CHANGELOG.md) for the
full release history.

## Features

- [x] SSRF-protected URL validation (checks all resolved IPv4/IPv6 addresses)
- [x] HTTP engine with timeout, bounded redirects, and retry handling
- [x] Security header detection (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] Missing-header recommendations + misconfiguration detection
- [x] Weighted risk scoring (per-finding severity + overall 0-100 score)
- [x] Console (rich) and JSON report generation
- [x] Full test suite - 59 tests, 95% coverage
- [x] CI pipeline (GitHub Actions, Python 3.10-3.12)

## Installation

```bash
git clone https://github.com/mrsadik2175/security-headers-analyzer.git
cd security-headers-analyzer
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Console report (default)
security-headers-analyzer --url https://example.com

# JSON output, for CI/automation
security-headers-analyzer --url https://example.com --format json

# Save a report to a file
security-headers-analyzer --url https://example.com --format json --output report.json

# Full option list
security-headers-analyzer --help
```

### Example output

```
$ security-headers-analyzer --url https://github.com

╭──────────────────────────── Security Header Scan ────────────────────────────╮
│ https://github.com                                                           │
│ HTTP 200   Score: 75.0/100   Risk: MEDIUM   Duration: 0.116s                 │
╰────────────────────────────────────────────────────────────────────────────╯
  Header                       Status            Severity   Recommendation
  Content-Security-Policy      ⚠ misconfigured   medium     Current value is weak (allows 'unsafe-inline', which
                                                              defeats CSP's main XSS protection). Recommended: ...
  Strict-Transport-Security    ✓ present         -          -
  X-Content-Type-Options       ✓ present         -          -
  X-Frame-Options              ✓ present         -          -
  Referrer-Policy              ✓ present         -          -
  Permissions-Policy           ✗ missing         low        Add header: Permissions-Policy: geolocation=(), ...
```

## Project Structure

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design overview.

## Security

This tool only sends a single, read-only HTTP GET request to URLs you
explicitly provide. It performs no exploitation, brute-forcing, or intrusive
testing - it is a passive header inspector, with SSRF protection enabled by
default. See [SECURITY.md](SECURITY.md) for the full responsible-use policy
and vulnerability reporting process.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
