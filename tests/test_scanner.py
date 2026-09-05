"""Tests for Scanner.validate_url() and Scanner.fetch_headers().

No real network calls are made - socket resolution and HTTP requests
are mocked so these tests run fast and offline, and so we can
deterministically test SSRF-protection branches (private IPs) without
needing actual internal infrastructure to point at."""

from unittest.mock import MagicMock, patch
import pytest
import requests
from security_headers_analyzer.core.config import REQUIRED_SECURITY_HEADERS
from security_headers_analyzer.core.exceptions import InvalidURLError, ScanRequestError
from security_headers_analyzer.core.models import HeaderFinding, HeaderStatus, RiskLevel
from security_headers_analyzer.core.scanner import Scanner


class TestValidateUrl:

    def test_rejects_non_http_scheme(self):
        scanner = Scanner("ftp://example.com")
        with pytest.raises(InvalidURLError, match="Unsupported URL scheme"):

            scanner.validate_url()

    def test_rejects_missing_hostname(self):
        scanner = Scanner("https:///path-only")

        with pytest.raises(InvalidURLError, match="missing a hostname"):
            scanner.validate_url()

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_rejects_loopback_address(self, mock_resolve):

        mock_resolve.return_value = "127.0.0.1"

        scanner = Scanner("http://localhost")

        with pytest.raises(InvalidURLError, match="SSRF protection"):

            scanner.validate_url()

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_rejects_cloud_metadata_ip(self, mock_resolve):

        # 169.254.169.254 is the well-known cloud metadata endpoint -
        # a classic SSRF target that must always be blocked by default.

        mock_resolve.return_value = "169.254.169.254"
        scanner = Scanner("http://metadata.internal")

        with pytest.raises(InvalidURLError, match="SSRF protection"):
            scanner.validate_url()

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_allows_private_ip_when_explicitly_enabled(self, mock_resolve):

        mock_resolve.return_value = "127.0.0.1"
        scanner = Scanner("http://localhost", allow_private=True)

        assert scanner.validate_url() is True

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_accepts_public_host(self, mock_resolve):

        mock_resolve.return_value = "93.184.216.34"
        scanner = Scanner("https://example.com")

        assert scanner.validate_url() is True

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_unresolvable_hostname_raises(self, mock_resolve):

        import socket

        mock_resolve.side_effect = socket.gaierror("Name or service not known")
        scanner = Scanner("https://this-domain-does-not-exist.invalid")
        with pytest.raises(InvalidURLError, match="Could not resolve hostname"):
            scanner.validate_url()


class TestFetchHeaders:

    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_returns_headers_as_plain_dict(self, mock_get):

        mock_response = MagicMock()
        mock_response.headers = {"Content-Type": "text/html", "X-Frame-Options": "DENY"}
        mock_response.status_code = 200

        mock_get.return_value = mock_response

        scanner = Scanner("https://example.com")
        headers = scanner.fetch_headers()

        assert headers["X-Frame-Options"] == "DENY"
        assert scanner._last_status_code == 200
        assert isinstance(headers, dict)

    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_timeout_raises_scan_request_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()
        scanner = Scanner("https://example.com")
        with pytest.raises(ScanRequestError, match="timed out"):
            scanner.fetch_headers()

    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_connection_error_raises_scan_request_error(self, mock_get):

        mock_get.side_effect = requests.exceptions.ConnectionError()
        scanner = Scanner("https://example.com")
        with pytest.raises(ScanRequestError, match="Could not connect"):
            scanner.fetch_headers()

    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_too_many_redirects_raises_scan_request_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.TooManyRedirects()
        scanner = Scanner("https://example.com")
        with pytest.raises(ScanRequestError, match="Too many redirects"):
            scanner.fetch_headers()


class TestDetectHeaders:
    def test_flags_all_headers_missing_on_empty_response(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({})

        assert len(findings) == len(REQUIRED_SECURITY_HEADERS)
        assert all(f.status == HeaderStatus.MISSING for f in findings)
        assert all(f.value is None for f in findings)

    def test_detects_present_header_with_value(self):
        scanner = Scanner("https://example.com")

        raw_headers = {"X-Frame-Options": "DENY"}
        findings = scanner.detect_headers(raw_headers)

        xfo = next(f for f in findings if f.header_name == "X-Frame-Options")
        assert xfo.status == HeaderStatus.PRESENT
        assert xfo.value == "DENY"

    def test_detection_is_case_insensitive(self):

        # Real servers are inconsistent about header casing -
        # detection must not miss a header just because of this.

        scanner = Scanner("https://example.com")
        raw_headers = {"content-security-policy": "default-src 'self'"}
        findings = scanner.detect_headers(raw_headers)

        csp = next(f for f in findings if f.header_name == "Content-Security-Policy")
        assert csp.status == HeaderStatus.PRESENT
        assert csp.value == "default-src 'self'"

    def test_mixed_present_and_missing(self):
        scanner = Scanner("https://example.com")
        raw_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }

        findings = scanner.detect_headers(raw_headers)

        present_names = {
            f.header_name for f in findings if f.status == HeaderStatus.PRESENT
        }
        missing_names = {
            f.header_name for f in findings if f.status == HeaderStatus.MISSING
        }

        assert "Strict-Transport-Security" in present_names
        assert "X-Content-Type-Options" in present_names
        assert "Content-Security-Policy" in missing_names
        assert "X-Frame-Options" in missing_names

    def test_unrelated_headers_are_ignored(self):
        # Headers outside our required set (e.g. Content-Type) should
        # not appear in findings at all - we only report on the
        # headers we actually check for.
        scanner = Scanner("https://example.com")
        raw_headers = {"Content-Type": "text/html", "Server": "nginx"}

        findings = scanner.detect_headers(raw_headers)

        reported_names = {f.header_name for f in findings}
        assert "Content-Type" not in reported_names
        assert "Server" not in reported_names


class TestAnalyzeFindings:
    """Tests Scanner.analyze_findings() -- Stage 4's recommendation +
    misconfiguration-detection logic."""

    def test_missing_header_gets_recommendation(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({})  # everything missing
        analyzed = scanner.analyze_findings(findings)

        xfo = next(f for f in analyzed if f.header_name == "X-Frame-Options")
        assert xfo.status == HeaderStatus.MISSING
        assert xfo.recommendation is not None
        assert "DENY" in xfo.recommendation

    def test_healthy_present_header_stays_present(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({"X-Content-Type-Options": "nosniff"})
        analyzed = scanner.analyze_findings(findings)

        finding = next(f for f in analyzed if f.header_name == "X-Content-Type-Options")
        assert finding.status == HeaderStatus.PRESENT
        assert finding.recommendation is None

    def test_csp_with_unsafe_inline_flagged_misconfigured(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers(
            {
                "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"
            }
        )
        analyzed = scanner.analyze_findings(findings)

        csp = next(f for f in analyzed if f.header_name == "Content-Security-Policy")
        assert csp.status == HeaderStatus.MISCONFIGURED
        assert "unsafe-inline" in csp.recommendation

    def test_csp_with_wildcard_flagged_misconfigured(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({"Content-Security-Policy": "default-src *"})
        analyzed = scanner.analyze_findings(findings)

        csp = next(f for f in analyzed if f.header_name == "Content-Security-Policy")
        assert csp.status == HeaderStatus.MISCONFIGURED

    def test_hsts_short_max_age_flagged_misconfigured(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({"Strict-Transport-Security": "max-age=60"})
        analyzed = scanner.analyze_findings(findings)

        hsts = next(f for f in analyzed if f.header_name == "Strict-Transport-Security")
        assert hsts.status == HeaderStatus.MISCONFIGURED
        assert "too short" in hsts.recommendation

    def test_hsts_long_max_age_stays_present(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers(
            {"Strict-Transport-Security": "max-age=63072000; includeSubDomains"}
        )
        analyzed = scanner.analyze_findings(findings)

        hsts = next(f for f in analyzed if f.header_name == "Strict-Transport-Security")
        assert hsts.status == HeaderStatus.PRESENT

    def test_x_frame_options_allowall_flagged_misconfigured(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({"X-Frame-Options": "ALLOWALL"})
        analyzed = scanner.analyze_findings(findings)

        xfo = next(f for f in analyzed if f.header_name == "X-Frame-Options")
        assert xfo.status == HeaderStatus.MISCONFIGURED

    def test_referrer_policy_unsafe_url_flagged_misconfigured(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({"Referrer-Policy": "unsafe-url"})
        analyzed = scanner.analyze_findings(findings)

        rp = next(f for f in analyzed if f.header_name == "Referrer-Policy")
        assert rp.status == HeaderStatus.MISCONFIGURED

    def test_permissions_policy_empty_value_flagged_misconfigured(self):
        scanner = Scanner("https://example.com")
        findings = scanner.detect_headers({"Permissions-Policy": ""})
        analyzed = scanner.analyze_findings(findings)

        pp = next(f for f in analyzed if f.header_name == "Permissions-Policy")
        assert pp.status == HeaderStatus.MISCONFIGURED
        assert "empty" in pp.recommendation


class TestScoreRisk:
    """Tests Scanner.score_risk() -- Stage 5's severity + overall scoring."""

    def test_all_headers_present_scores_perfect_and_low_risk(self):
        scanner = Scanner("https://example.com")
        findings = [
            HeaderFinding(name, HeaderStatus.PRESENT, value="ok")
            for name in REQUIRED_SECURITY_HEADERS
        ]
        overall_risk, score = scanner.score_risk(findings)

        assert score == 100.0
        assert overall_risk == RiskLevel.LOW
        assert all(f.severity == RiskLevel.INFO for f in findings)

    def test_all_headers_missing_scores_zero_and_critical_risk(self):
        scanner = Scanner("https://example.com")
        findings = [
            HeaderFinding(name, HeaderStatus.MISSING)
            for name in REQUIRED_SECURITY_HEADERS
        ]
        overall_risk, score = scanner.score_risk(findings)

        assert score == 0.0
        assert overall_risk == RiskLevel.CRITICAL

    def test_missing_high_weight_header_gets_high_severity(self):
        scanner = Scanner("https://example.com")
        findings = [HeaderFinding("Content-Security-Policy", HeaderStatus.MISSING)]
        scanner.score_risk(findings)

        assert findings[0].severity == RiskLevel.HIGH

    def test_missing_low_weight_header_gets_low_severity(self):
        scanner = Scanner("https://example.com")
        findings = [HeaderFinding("X-Content-Type-Options", HeaderStatus.MISSING)]
        scanner.score_risk(findings)

        assert findings[0].severity == RiskLevel.LOW

    def test_misconfigured_scores_better_than_missing(self):
        # A weak-but-present header should never score worse than a
        # fully absent one which partial protection is still worth something.
        scanner = Scanner("https://example.com")

        missing_findings = [
            HeaderFinding("Content-Security-Policy", HeaderStatus.MISSING)
        ]
        _, missing_score = scanner.score_risk(missing_findings)

        misconfigured_findings = [
            HeaderFinding(
                "Content-Security-Policy", HeaderStatus.MISCONFIGURED, value="weak"
            )
        ]
        _, misconfigured_score = scanner.score_risk(misconfigured_findings)

        assert misconfigured_score > missing_score

    def test_single_missing_low_weight_header_stays_near_top_of_scale(self):
        # Losing only the lowest-weight header shouldn't tank the score
        # to CRITICAL/HIGH: it should land just under the perfect-score
        # LOW threshold, in MEDIUM, not collapse further.
        scanner = Scanner("https://example.com")
        findings = [
            HeaderFinding(name, HeaderStatus.PRESENT, value="ok")
            for name in REQUIRED_SECURITY_HEADERS
            if name != "X-Content-Type-Options"
        ]
        findings.append(HeaderFinding("X-Content-Type-Options", HeaderStatus.MISSING))
        overall_risk, score = scanner.score_risk(findings)

        assert score > 85.0
        assert overall_risk in (RiskLevel.LOW, RiskLevel.MEDIUM)


class TestRunIntegration:
    """Tests Scanner.run() end-to-end with the network layer mocked."""

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")
    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_run_populates_raw_headers_on_success(self, mock_get, mock_resolve):
        mock_resolve.return_value = "93.184.216.34"

        mock_response = MagicMock()
        mock_response.headers = {"X-Content-Type-Options": "nosniff"}
        mock_response.status_code = 200

        mock_get.return_value = mock_response

        scanner = Scanner("https://example.com")
        result = scanner.run()
        assert result.error is None
        assert result.status_code == 200
        assert result.raw_headers["X-Content-Type-Options"] == "nosniff"

    def test_run_sets_error_on_invalid_url(self):
        scanner = Scanner("ftp://example.com")
        result = scanner.run()

        assert result.error is not None
        assert result.status_code is None
        assert result.raw_headers == {}
