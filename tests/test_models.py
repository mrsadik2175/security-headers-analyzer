"""
Sanity tests for core.models.

These don't test network or detection logic (that arrives in later
stages) - they lock down the data model contract so future stages
can't silently change field names/ types without a test failing."""

from security_headers_analyzer.core.models import (
    HeaderFinding,
    HeaderStatus,
    RiskLevel,
    ScanResult,
)


def test_header_finding_default():
    finding = HeaderFinding(
        header_name="Content-Security-Policy",
        status=HeaderStatus.MISSING,
    )

    assert finding.value is None
    assert finding.severity == RiskLevel.INFO


def test_scan_result_missing_headers_filter():
    result = ScanResult(
        target_url="https://example.com",
        findings=[
            HeaderFinding("X-Frame-Options", HeaderStatus.MISSING),
            HeaderFinding("Strict-Transport-Security", HeaderStatus.PRESENT),
            HeaderFinding("Referrer-Policy", HeaderStatus.MISCONFIGURED),
        ],
    )

    assert len(result.missing_headers) == 1
    assert result.missing_headers[0].header_name == "X-Frame-Options"
    assert len(result.misconfigured_headers) == 1


def test_scan_result_defaults_to_info_risk():
    result = ScanResult(target_url="https://example.com")
    assert result.overall_risk == RiskLevel.INFO
    assert result.findings == []
