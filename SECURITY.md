# Security Policy

## Responsible Use

`security-headers-analyzer` is a **passive** scanner: it sends a single
read-only HTTP GET request to a target URL and inspects the response
headers. It performs no exploitation, brute-forcing, fuzzing, or
intrusive testing of any kind.

That said, **only scan URLs you own or have explicit permission to
test.** Scanning third-party systems without authorization may violate
laws such as the U.S. Computer Fraud and Abuse Act (CFAA) or equivalent
legislation in your jurisdiction, and may violate the target's terms
of service, regardless of how passive the scan is.

## Built-in Protections

This tool includes several safeguards by default:

- **SSRF protection** — refuses to scan hostnames that resolve to
  private, loopback, link-local, or reserved IP addresses (including
  cloud metadata endpoints) unless `--allow-private` is explicitly
  passed. This check validates *all* resolved addresses (IPv4 and
  IPv6), not just the first one.
- **Honest identification** — requests are sent with a clear,
  non-spoofed User-Agent (`security-headers-analyzer/<version>`) so
  target operators can identify the traffic.
- **Bounded requests** — a capped redirect limit and a conservative,
  narrowly-scoped retry policy (transient 5xx errors only) prevent the
  tool from generating excessive traffic against a single target.
- **No sensitive data in reports** — raw response headers (which may
  include `Set-Cookie` or other sensitive values) are never included
  in generated reports; only the specific security headers this tool
  checks are surfaced.

## Reporting a Vulnerability

If you discover a security vulnerability in this project itself
(as opposed to in a site you scan with it), please **do not open a
public issue**. Instead:

1. Open a private [GitHub Security Advisory](../../security/advisories/new)
   on this repository, or
2. Email the maintainer directly (see repository profile) with a
   description of the issue and steps to reproduce.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal example is ideal)
- Any suggested remediation, if you have one

We aim to acknowledge reports within 5 business days.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌ (pre-release, not maintained) |
