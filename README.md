# security-headers-analyzer

A command line tool that analyzes the HTTP security headers of any given URL,
identifies missing or misconfigured headers, scores the associated risk, and
generates a clear, actionable report.

Inspired by tools like [securityheaders.com](https://securityheaders.com) and
the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
built as a self-contained learning + portfolio project.

## Status

🚧 Under active development. See [Milestones](../../milestones) for progress.

## Features (planned)

- [x] Project architecture & data models
- [ ] URL validation + HTTP request engine
- [ ] Security header detection (CSP, HSTS, X-Frame-Options, etc.)
- [ ] Missing / misconfigured header analysis
- [ ] Weighted risk scoring
- [ ] Human-readable + JSON report generation
- [ ] Full test suite

## Installation

```bash
git clone https://github.com/mrsadik2175/security-headers-analyzer.git
cd security-headers-analyzer
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Usage (coming in later stages)

```bash
security-headers-analyzer --url https://example.com
```

## Project Structure

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design overview.

## Security

This tool only sends read-only HTTP requests to URLs you explicitly provide.
It performs no exploitation, brute-forcing, or intrusive testing - it is a
passive header inspector. See `SECURITY.md` (added in a later stage) for the
responsible-use policy.

## License

MIT — see [LICENSE](LICENSE).
