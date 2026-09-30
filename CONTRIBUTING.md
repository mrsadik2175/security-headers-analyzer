# Contributing

Thanks for considering contributing to `security-headers-analyzer`!

## Getting Started

```bash
git clone https://github.com/mrsadik2175/security-headers-analyzer.git
cd security-headers-analyzer
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
pip install -r requirements.txt
```

## Running Tests

```bash
python -m pytest tests/ -v --cov=security_headers_analyzer --cov-report=term-missing
```

Please keep coverage high - new logic should come with new tests,
not just a passing existing suite.

## Making a Change

1. Fork the repository and create a branch off `main`:
   `git checkout -b feat/short-description`
2. Make your change. Keep commits focused and use
   [Conventional Commits](https://www.conventionalcommits.org/) style
   (`feat: ...`, `fix: ...`, `test: ...`, `chore: ...`, `docs: ...`).
3. Add or update tests for any behavior change.
4. Run the full test suite locally and make sure it passes.
5. Open a pull request against `main` describing:
   - **Summary** — what changed and why
   - **Testing** — how you verified it
   - **Security impact** — does this touch network requests, URL
     handling, or reporting? Call it out explicitly.

## Code Style

- Python 3.9+ compatible, type-hinted where practical.
- Favor small, single-responsibility functions (see `core/scanner.py`'s
  per-header weakness checkers for the pattern this project follows).
- Security-sensitive logic (URL validation, SSRF checks, header
  parsing) should have explicit, named test cases for edge cases —
  not just happy-path coverage.

## Reporting Bugs vs. Security Issues

- **Regular bugs** (incorrect header detection, a crash, a
  documentation error): open a GitHub issue.
- **Security vulnerabilities** in the tool itself: see
  [SECURITY.md](SECURITY.md) — please do not open a public issue.

## Questions

Open a [discussion](../../discussions) or an issue tagged `question`.
