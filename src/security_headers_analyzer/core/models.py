"""

core.models
~~~~~~~~~~~


Shared data structures used across the entire tool.

Defining these up front (Stage 1) means every later stage - the HTTP
engine, the header detector, the risk scorer, and the report generator -
all speak the same typed "language" instead of passing around loose
dicts. This reduces bugs and makes the codebase self-documenting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class RiskLevel(str, Enum):
    """Overall risk classification for a scanned target.

    Ordered from least to most severe. Stored as ``str`` so it can be
    serialized directly to JSON without a custom encoder.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HeaderStatus(str, Enum):
    """Result of checking a single security header."""

    PRESENT = "present"  # header exists and looks correctly configured
    MISSING = "missing"  # header absent entirely
    MISCONFIGURED = "misconfigured"  # header exists but is weak/incorrect


@dataclass
class HeaderFinding:
    """The analysis result for one individual security header.

    Populated by the header-detection logic in Stage 3 and consumed by
    the risk scorer (Stage 5) and report generator (Stage 6).


    """

    header_name: str
    status: HeaderStatus
    value: str | None = None  # raw header value, if present
    recommendation: str | None = None  # what the user should set instead
    severity: RiskLevel = RiskLevel.INFO


@dataclass
class ScanResult:
    """The complete result of scanning a single URL.

    This is the top level object that gets serialized to the final
    report (Stage 6) and printed to the CLI.
    """

    target_url: str
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status_code: int | None = None
    raw_headers: dict[str, str] = field(default_factory=dict)  # added in the Stage 2
    findings: list[HeaderFinding] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.INFO
    error: str | None = None  # populated if the scan failed (e.g. connection error)

    @property
    def missing_headers(self) -> list[HeaderFinding]:
        """Convenience accessor used heavily by the report generator."""
        return [f for f in self.findings if f.status == HeaderStatus.MISSING]

    @property
    def misconfigured_headers(self) -> list[HeaderFinding]:
        return [f for f in self.findings if f.status == HeaderStatus.MISCONFIGURED]
