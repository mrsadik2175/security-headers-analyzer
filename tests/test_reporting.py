"""
Tests for reporting.console_report and reporting.json_report."""

import io
import json
from rich.console import Console
from security_headers_analyzer.core.models import (
    HeaderFinding,
    HeaderStatus,
    RiskLevel,
    ScanResult,
)
from security_headers_analyzer.reporting.console_report import render_console_report
from security_headers_analyzer.reporting.json_report import (
    render_json_report,
    result_to_dict,
)


def _sample_result() -> ScanResult:

    result = ScanResult(target_url="https://example.com", status_code=200)
    result.raw_headers = {"Set-Cookie": "session=super-secret-token; HttpOnly"}

    result.findings = [
        HeaderFinding(
            header_name="Content-Security-Policy",
            status=HeaderStatus.MISCONFIGURED,
            value="default-src *",
            recommendation="Current value is weak. Recommended: default-src 'self'",
            severity=RiskLevel.MEDIUM,
        ),
        HeaderFinding(
            header_name="X-Frame-Options",
            status=HeaderStatus.MISSING,
            recommendation="Add header: X-Frame-Options: DENY",
            severity=RiskLevel.MEDIUM,
        ),
        HeaderFinding(
            header_name="X-Content-Type-Options",
            status=HeaderStatus.PRESENT,
            value="nosniff",
            severity=RiskLevel.INFO,
        ),
    ]

    result.overall_risk = RiskLevel.MEDIUM
    result.security_score = 65.0

    return result


class TestJsonReport:

    def test_result_to_dict_has_expected_top_level_keys(self):
        data = result_to_dict(_sample_result())

        assert set(data.keys()) == {
            "target_url",
            "scanned_at",
            "status_code",
            "overall_risk",
            "security_score",
            "error",
            "findings",
        }

    def test_enums_serialized_as_plain_strings(self):
        data = result_to_dict(_sample_result())
        assert data["overall_risk"] == "medium"

        assert data["findings"][0]["status"] == "misconfigured"
        assert data["findings"][0]["severity"] == "medium"

    def test_raw_headers_excluded_from_report(self):
        """Security requirement: raw response headers (which may contain Set-Cookie/session data) must never leak into the
        exported report."""

        data = result_to_dict(_sample_result())
        assert "raw_headers" not in data
        serialized = render_json_report(_sample_result())
        assert "super-secret-token" not in serialized

    def test_render_json_report_is_valid_json(self):
        serialized = render_json_report(_sample_result())
        parsed = json.loads(serialized)  # raises if invalid
        assert parsed["target_url"] == "https://example.com"
        assert len(parsed["findings"]) == 3

    def test_error_result_serializes_cleanly(self):
        result = ScanResult(
            target_url="ftp://bad-url", error="Unsupported URL scheme 'ftp'."
        )
        data = result_to_dict(result)

        assert data["error"] == "Unsupported URL scheme 'ftp'."
        assert data["findings"] == []


class TestConsoleReport:
    def _render_to_string(self, result: ScanResult) -> str:
        buffer = io.StringIO()
        console = Console(file=buffer, width=100, force_terminal=False)
        render_console_report(result, console=console)

        return buffer.getvalue()

    def test_includes_target_url_and_risk_level(self):
        output = self._render_to_string(_sample_result())
        assert "example.com" in output
        assert "MEDIUM" in output

    def test_includes_all_header_names(self):
        output = self._render_to_string(_sample_result())
        assert "Content-Security-Policy" in output
        assert "X-Frame-Options" in output
        assert "X-Content-Type-Options" in output

    def test_includes_recommendation_text(self):
        output = self._render_to_string(_sample_result())
        assert "Add header: X-Frame-Options: DENY" in output

    def test_error_result_shows_failure_panel_not_table(self):
        result = ScanResult(
            target_url="ftp://bad-url", error="Unsupported URL scheme 'ftp'."
        )
        output = self._render_to_string(result)
        assert "Scan failed" in output
        assert "Unsupported URL scheme" in output

    def test_does_not_leak_raw_header_values(self):
        # Same security guarantee as the JSON report - raw_headers
        # should never appear in the rendered console output either.
        output = self._render_to_string(_sample_result())

        assert "super-secret-token" not in output
