"""
reporting.json_report
~~~~~~~~~~~~~~~~~~~~~~

Machine-readable JSON export of a ScanResult -- intended for CI
pipelines, dashboards, or piping into other tools (``jq``, etc).

Security note: this deliberately does NOT include ``raw_headers`` in
the exported report. Raw response headers can carry sensitive values
(``Set-Cookie``, auth-related headers, internal server banners) that
have nothing to do with the security-header findings themselves.
Reports are often shared more widely than the scan session that
produced them (attached to tickets, posted in chat, committed to a
repo) - the export only includes the header names/statuses/values we
intentionally analyzed, not an unfiltered dump of everything the
server sent back."""

from __future__ import annotations
import json

from security_headers_analyzer.core.models import HeaderFinding, ScanResult


def finding_to_dict(finding: HeaderFinding) -> dict:
    """Serialize a single  HeaderFinding to a plain, JSON-safe dict."""
    return {
        "header_name": finding.header_name,
        "status": finding.status.value,
        "value": finding.value,
        "recommendation": finding.recommendation,
        "severity": finding.severity.value,
    }


def result_to_dict(result: ScanResult) -> dict:
    """Serialize a ScanResult to a plain, JSON-safe dict.


    Note: intentionally excludes ``raw_headers`` - see module docstring.
    """

    return {
        "target_url": result.target_url,
        "scanned_at": result.scanned_at.isoformat(),
        "status_code": result.status_code,
        "overall_risk": result.overall_risk.value,
        "security_score": result.security_score,
        "error": result.error,
        "findings": [finding_to_dict(f) for f in result.findings],
    }


def render_json_report(result: ScanResult, *, indent: int = 2) -> str:
    """Render a ScanResult as a formatted JSON string."""
    return json.dumps(result_to_dict(result), indent=indent)


def write_json_report(result: ScanResult, path: str, *, indent: int = 2) -> None:
    """Render and write a ScanResult's JSON report to ``path``."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_json_report(result, indent=indent))
        f.write("\n")
