# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - Production Release

First stable release. Summary of the full build-out across 8 stages:

### Added
- Passive HTTP security header scanner for a single target URL
- SSRF-protected URL validation (checks all resolved IPv4/IPv6
  addresses against private/loopback/reserved/metadata ranges)
- HTTP engine with timeout, bounded redirects, and conservative retry
  policy for transient (502/503/504) errors
- Detection of six key security headers: Content-Security-Policy,
  Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy
- Missing-header recommendations and misconfiguration detection
  (weak CSP directives, short HSTS max-age, non-standard
  X-Frame-Options, unsafe Referrer-Policy, empty Permissions-Policy)
- Weighted risk scoring: per-finding severity + overall 0-100 security
  score mapped to a risk level (low/medium/high/critical)
- Console report (rich-formatted) and JSON report export, selectable
  via `--format`, with optional `--output` to write to a file
- Scan duration tracking
- GitHub Actions CI pipeline (Python 3.10-3.12) with coverage reporting
- SECURITY.md, CONTRIBUTING.md, and this changelog

### Fixed
- SSRF validation gap: the original check only validated the first
  resolved IPv4 address; a hostname resolving solely to an IPv6
  address, or to multiple mixed public/private A records, could
  bypass the private-address block. Now validates every resolved
  address via `socket.getaddrinfo`.

### Security
- Raw response headers are never included in exported reports, to
  avoid leaking sensitive values (e.g. `Set-Cookie`) into shared output
- All outbound requests identify honestly via a non-spoofed User-Agent

---

## Stage-by-stage release history

- **v0.7.0** — Testing hardening: SSRF fix (all resolved IPs, IPv4+IPv6),
  retry logic for transient failures, scan duration tracking, CI
  pipeline with coverage reporting (95%)
- **v0.6.0** — Report generation: rich console report + JSON export,
  `--format`/`--output` flags, raw headers excluded from all reports
- **v0.5.0** — Weighted risk scoring: per-finding severity, overall
  0-100 security score, risk level classification
- **v0.4.0** — Missing-header analysis: concrete recommendations for
  missing headers, misconfiguration detection for present-but-weak
  header values
- **v0.3.0** — Security header detection: case-insensitive comparison
  against the required header set
- **v0.2.0** — URL validation and HTTP engine: SSRF protection,
  bounded redirects, specific exception handling
- **v0.1.0** — Initial project scaffold: architecture, core data
  models, CLI stub, logging, test suite
