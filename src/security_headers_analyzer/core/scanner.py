"""
core.scanner

~~~~~~~~~~~~


The orchestrator class that ties the whole pipeline together:

    URL validation -> HTTP request -> header detection -> analysis -> risk scoring -> report

Stage 2 implements ``validate_url()`` and ``fetch_headers()``.
Stage 3 implements ``detect_headers()``. Stage 4 implements
``analyze_findings()``, which turns raw present/missing findings into
actionable recommendations and flags present-but-weak headers as
MISCONFIGURED. ``score_risk()`` remains a stub until Stage 5.
"""

from __future__ import annotations
import ipaddress
import logging
import socket
import re
from urllib.parse import urlparse
import requests
from security_headers_analyzer.core.config import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_USER_AGENT,
    HEADER_RECOMMENDATIONS,
    HEADER_RISK_WEIGHT,
    MAX_REDIRECTS,
    MIN_HSTS_MAX_AGE_SECONDS,
    MISCONFIGURED_PENALTY_FACTOR,
    REQUIRED_SECURITY_HEADERS,
    RISK_LEVEL_THRESHOLDS,
)

from security_headers_analyzer.core.exceptions import InvalidURLError, ScanRequestError
from security_headers_analyzer.core.models import (
    HeaderFinding,
    HeaderStatus,
    RiskLevel,
    ScanResult,
)

logger = logging.getLogger(__name__)
ALLOWED_SCHEMES = {"http", "https"}

# -------- Stage 4: weakness checkers -----
# Each function takes a present header's raw value and returns a short
# human-readable reason string if the value is weak/misconfigured, or
# None if the value looks fine. Kept as small, independently testable
# functions rather than one giant if/elif block.


def _check_csp_weakness(value: str) -> str | None:
    lowered = value.lower()
    if "unsafe-inline" in lowered:
        return "allows 'unsafe-inline', which defeats CSP's main XSS protection"
    if "unsafe-eval" in lowered:
        return "allows 'unsafe-eval', enabling dynamic code execution"
    # A bare wildcard as a source value (e.g. "default-src *") allows
    # loading from ANY origin, which is close to having no CSP at all.

    if re.search(r"(?:^|\s)\*(?:\s|;|$)", lowered):
        return "uses a bare wildcard '*' source, allowing any origin"
    return None


def _check_hsts_weakness(value: str) -> str | None:
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if not match:
        return "missing a valid 'max-age' directive"
    max_age = int(match.group(1))
    if max_age < MIN_HSTS_MAX_AGE_SECONDS:
        return f"max-age={max_age}s is too short (recommend >= {MIN_HSTS_MAX_AGE_SECONDS}s / ~6 months)"
    return None


def _check_x_content_type_options_weakness(value: str) -> str | None:
    if value.strip().lower() != "nosniff":
        return f"value '{value}' is not the required 'nosniff'"
    return None


def _check_x_frame_options_weakness(value: str) -> str | None:
    if value.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return f"value '{value}' is non-standard/weak (expected DENY or SAMEORIGIN)"
    return None


def _check_referrer_policy_weakness(value: str) -> str | None:
    # unsafe-url leaks the full URL (including paths/query strings)
    # cross-origin and over plain HTTP which the most permissive, riskiest
    # setting this header can have.
    if value.strip().lower() == "unsafe-url":
        return "'unsafe-url' leaks full referrer data cross-origin, including over HTTP"
    return None


def _check_permissions_policy_weakness(value: str) -> str | None:
    if value.strip() == "":
        return "present but empty — restricts nothing"

    return None


# Dispatch table: header name -> weakness checker. Headers with no
# entry here are treated as "no additional value-quality check yet."
_WEAKNESS_CHECKERS = {
    "Content-Security-Policy": _check_csp_weakness,
    "Strict-Transport-Security": _check_hsts_weakness,
    "X-Content-Type-Options": _check_x_content_type_options_weakness,
    "X-Frame-Options": _check_x_frame_options_weakness,
    "Referrer-Policy": _check_referrer_policy_weakness,
    "Permissions-Policy": _check_permissions_policy_weakness,
}


# --- Stage 5: risk scoring ---------------------------------------------------


def _severity_for_finding(header_name: str, status: HeaderStatus) -> RiskLevel:
    """Map a single finding to a per-header severity level.

    Based on the header's configured risk weight (how impactful it is
    if broken) and whether it's fully missing (worse) or merely
    misconfigured (partial protection still exists).
    """
    if status == HeaderStatus.PRESENT:
        return RiskLevel.INFO

    weight = HEADER_RISK_WEIGHT.get(header_name, 0)

    if status == HeaderStatus.MISSING:
        if weight >= 20:
            return RiskLevel.HIGH
        if weight >= 15:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    # MISCONFIGURED - a weak header is bad, but still one severity
    # tier better than not having it at all.
    if weight >= 20:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _risk_level_from_score(percentage: float) -> RiskLevel:
    """Map an overall security_score percentage to a RiskLevel using
    the ordered thresholds in config.RISK_LEVEL_THRESHOLDS.
    """
    for threshold, level_value in RISK_LEVEL_THRESHOLDS:
        if percentage >= threshold:
            return RiskLevel(level_value)
    return (
        RiskLevel.CRITICAL
    )  # unreachable given a 0.0 floor threshold, but safe default


class Scanner:
    """Coordinates a single-URL security header scan."""

    def __init__(
        self,
        target_url: str,
        timeout: float | None = None,
        allow_private: bool = False,
    ) -> None:
        self.target_url = target_url
        self.timeout = timeout or DEFAULT_TIMEOUT_SECONDS
        #  SSRF guard toggle: only meant for local/dev testing against
        # e.g http://localhost:8000. Never enable this in a shared

        # or production deployment of the tool.

        self.allow_private = allow_private
        self._last_status_code: int | None = None
        logger.debug("Scanner initialized for target=%s", self.target_url)

    # ---- Stage 2: URL validation ---------------------------------------------------
    def validate_url(self) -> bool:
        """Validate ``self.target_url`` is a safe, well-formed HTTP(S) URL.

        Two layer of validation:
          1. Structural - must be http(s), must have a hostname.
          2. Network (SSRF guard) - the hostname must not resolve to a
             private, loopback, link-local, or otherwise reserved IP,
             unless ``allow_private`` was explicitly set.

        Raises:
            InvalidURLError: if either check fails.
        """

        parsed = urlparse(self.target_url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise InvalidURLError(
                f"Unsupported URL scheme '{parsed.scheme or '(none)'}'. "
                f"Only {sorted(ALLOWED_SCHEMES)} are allowed."
            )

        hostname = parsed.hostname
        if not hostname:
            raise InvalidURLError("URL is missing a hostname.")
        if not self.allow_private:
            self._assert_public_host(hostname)

        return True

    @staticmethod
    def _assert_public_host(hostname: str) -> None:
        """Resolve ``hostname`` and reject it if it points at a
        private/internal address. This is the tool's core SSRF defense:
        without it, a user (or an attacker feeding this tool a URL)
        could point the scanner at internal infrastructure like
        ``http://169.254.169.254`` (cloud metadata endpoints) or
        ``http://localhost:6379`` (internal services)."""

        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror as exc:
            raise InvalidURLError(
                f"Could not resolve hostname '{hostname}': {exc}"
            ) from exc

        ip_obj = ipaddress.ip_address(resolved_ip)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            raise InvalidURLError(
                f"Refusing to scan '{hostname}' ->{resolved_ip}: "
                "resolves to a private/internal address (SSRF protection). "
                "Pass allow_private=True only for local development."
            )

    # --- Stage 2: HTTP engine -----------------------------------------------------
    def fetch_headers(self) -> dict[str, str]:
        """Perform the HTTP request and return raw response headers.
        Uses a dedicated ``requests.Session`` with a capped redirect
        count and an explicit User-Agent (so the tool identifies
        itself honestly rather than spoofing a browser)."""

        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        try:
            response = session.get(
                self.target_url,
                timeout=self.timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=True,
            )
        except requests.exceptions.Timeout as exc:
            raise ScanRequestError(
                f"Request to {self.target_url} timed out after {self.timeout}s"
            ) from exc
        except requests.exceptions.TooManyRedirects as exc:

            raise ScanRequestError(
                f"Too many redirects (limit={MAX_REDIRECTS}) for {self.target_url}"
            ) from exc
        except requests.exceptions.SSLError as exc:
            raise ScanRequestError(
                f"TLS/SSL error connecting to {self.target_url}: {exc}"
            ) from exc
        except requests.exceptions.ConnectionError as exc:

            raise ScanRequestError(
                f"Could not connect to {self.target_url}: {exc}"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise ScanRequestError(
                f"Request to {self.target_url} failed: {exc}"
            ) from exc
        self._last_status_code = response.status_code
        # requests.Response.headers is a case-insensitive dict already;
        #  cast to a plain dict for a stable, serializable return type.

        return dict(response.headers)

    # ---- Stubs for later stages -----------------------------------------------

    def detect_headers(self, raw_headers: dict[str, str]) -> list[HeaderFinding]:
        """Compare raw headers against the expected security header set.

        Classifies each header in ``REQUIRED_SECURITY_HEADERS`` as
        PRESENT or MISSING and captures its raw value when present.

        Deliberately narrow in scope: this stage does NOT judge whether
        a *present* header's value is actually safe (e.g. a weak CSP
        like ``default-src *``) - that misconfiguration analysis is
        Stage 4's responsibility. Mixing "is it there" with "is it any
        good" into one method makes both harder to test in isolation.

        Note on case-insensitivity: HTTP header names are
        case-insensitive per RFC 7230, but servers are inconsistent
        about how they capitalize them (``Content-Security-Policy`` vs
        ``content-security-policy``). We normalize both sides to
        lowercase for the lookup so detection doesn't silently miss a
        header just because a server capitalizes it differently.
        """
        # Map lowercase header name -> (original-case name, value) so we
        # can look things up case-insensitively but still report the
        # server's actual casing back if we ever need it.
        normalized = {
            name.lower(): (name, value) for name, value in raw_headers.items()
        }

        findings: list[HeaderFinding] = []
        for expected_name in REQUIRED_SECURITY_HEADERS:
            match = normalized.get(expected_name.lower())
            if match is not None:
                _, value = match
                findings.append(
                    HeaderFinding(
                        header_name=expected_name,
                        status=HeaderStatus.PRESENT,
                        value=value,
                    )
                )

            else:
                findings.append(
                    HeaderFinding(
                        header_name=expected_name,
                        status=HeaderStatus.MISSING,
                    )
                )

        logger.debug(
            "Detected %d/%d required security headers present",
            sum(1 for f in findings if f.status == HeaderStatus.PRESENT),
            len(findings),
        )

        return findings

    def analyze_findings(self, findings: list[HeaderFinding]) -> list[HeaderFinding]:
        """Enrich detection findings with actionable analysis.

        For MISSING headers: attach a concrete recommended value.
        For PRESENT headers: run a per-header weakness check against
        the actual value; if weak, flip status to MISCONFIGURED and
        attach both the reason and the recommended fix.

        Mutates and returns the same list (findings are already fresh
        objects from ``detect_headers()``, so in-place enrichment here
        keeps the pipeline simple without extra copying).
        """
        for finding in findings:
            recommended_value = HEADER_RECOMMENDATIONS.get(finding.header_name)

            if finding.status == HeaderStatus.MISSING:
                finding.recommendation = (
                    f"Add header: {finding.header_name}: {recommended_value}"
                )
                continue

            if finding.status == HeaderStatus.PRESENT and finding.value is not None:
                checker = _WEAKNESS_CHECKERS.get(finding.header_name)
                if checker is None:
                    continue
                weakness_reason = checker(finding.value)
                if weakness_reason is not None:
                    finding.status = HeaderStatus.MISCONFIGURED
                    finding.recommendation = (
                        f"Current value is weak ({weakness_reason}). "
                        f"Recommended: {finding.header_name}: {recommended_value}"
                    )

        logger.debug(
            "Analysis complete: %d misconfigured, %d missing, %d OK",
            sum(1 for f in findings if f.status == HeaderStatus.MISCONFIGURED),
            sum(1 for f in findings if f.status == HeaderStatus.MISSING),
            sum(1 for f in findings if f.status == HeaderStatus.PRESENT),
        )
        return findings

    def score_risk(self, findings: list[HeaderFinding]) -> tuple[RiskLevel, float]:
        """Compute per- finding severity and an overall risk score.

        Scoring model: start from the total possible header weight
        (sum of ``HEADER_RISK_WEIGHT``). Each MISSING header deducts
        its full weight; each MISCONFIGURED header deducts a fraction
        of its weight (``MISCONFIGURED_PENALTY_FACTOR``) since a weak
        header still offers partial protection. The remaining
        percentage of the total is the ``security_score``, which maps
        to an overall ``RiskLevel`` via ``RISK_LEVEL_THRESHOLDS``.

        Mutates each finding's ``severity`` in place (same pattern as
        ``analyze_findings``) and returns ``(overall_risk, security_score)``
        for the caller to store on the ScanResult.
        """
        total_possible_weight = sum(HEADER_RISK_WEIGHT.values())
        deduction = 0.0

        for finding in findings:
            finding.severity = _severity_for_finding(
                finding.header_name, finding.status
            )

            weight = HEADER_RISK_WEIGHT.get(finding.header_name, 0)
            if finding.status == HeaderStatus.MISSING:
                deduction += weight
            elif finding.status == HeaderStatus.MISCONFIGURED:
                deduction += weight * MISCONFIGURED_PENALTY_FACTOR

        remaining_weight = max(0.0, total_possible_weight - deduction)
        security_score = (
            round((remaining_weight / total_possible_weight) * 100, 1)
            if total_possible_weight
            else 100.0
        )
        overall_risk = _risk_level_from_score(security_score)

        logger.debug(
            "Risk scoring complete: score=%.1f%%, overall_risk=%s",
            security_score,
            overall_risk.value,
        )
        return overall_risk, security_score

    # -- Orchestration (partially wired) ----------------------------------

    def run(self) -> ScanResult:
        """Execute the pipeline as far as it's implemented.


        Currently: validate -> fetch. The returned ScanResult carries
        ``raw_headers`` and ``status_code`` populated, with detection
        and scoring left for Stages 3-5 to fill in ``findings`` and
        ``overall_risk``."""

        result = ScanResult(target_url=self.target_url)

        try:

            self.validate_url()
            raw_headers = self.fetch_headers()
        except (InvalidURLError, ScanRequestError) as exc:
            result.error = str(exc)
            logger.error("Scan failed for %s: %s", self.target_url, exc)

            return result

        result.status_code = self._last_status_code
        result.raw_headers = raw_headers

        logger.info(
            "Fetched %d response headers from %s (HTTP %s)",
            len(raw_headers),
            self.target_url,
            result.status_code,
        )

        result.findings = self.detect_headers(raw_headers)
        result.findings = self.analyze_findings(result.findings)
        present_count = sum(
            1 for f in result.findings if f.status == HeaderStatus.PRESENT
        )
        misconfigured_count = sum(
            1 for f in result.findings if f.status == HeaderStatus.MISCONFIGURED
        )
        missing_count = sum(
            1 for f in result.findings if f.status == HeaderStatus.MISSING
        )
        logger.info(
            "Analysis complete: %d OK, %d misconfigured, %d missing (of %d checked)",
            present_count,
            misconfigured_count,
            missing_count,
            len(result.findings),
        )

        result.overall_risk, result.security_score = self.score_risk(result.findings)
        logger.info(
            "Overall risk: %s (security score: %.1f/100)",
            result.overall_risk.value.upper(),
            result.security_score,
        )

        # Report generation(Stage 6)lands next.
        return result
