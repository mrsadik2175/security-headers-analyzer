"""
core.config
~~~~~~~~~~~

Central place for constants and tunables. Keeping these out of the
logic files means Stage 3 (detection) and Stage 5 (scoring) can be
tuned or extended without touching business logic.
"""

from __future__ import annotations

# --- Network behavior (used by the HTTP engine in the Stage 2) ---------------

DEFAULT_TIMEOUT_SECONDS: float = 10.0
DEFAULT_USER_AGENT: str = "security-headers-analyzer/0.1  (+passive scanner)"
MAX_REDIRECTS: int = 5

# --- Security headers we will check (implemented in Stage 3) -------------
# Kept here now so the architecture is visible from Stage 1, even though
# the detection logic itself lands in a later stage.

REQUIRED_SECURITY_HEADERS: tuple[str, ...] = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

# --- Risk scoring weights (implemented in the Stage 5) ------------------------
# Higher weight= more impactful if the header is missing/misconfigured.

HEADER_RISK_WEIGHT: dict[str, int] = {
    "Content-Security-Policy": 25,
    "Strict-Transport-Security": 20,
    "X-Content-Type-Options": 10,
    "X-Frame-Options": 15,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
}
""" ------ Recommended values, used by Stage 4's analysis to generate fixes ------
 One good example value per header - not the only valid value, but a
 safe, sensible default we can confidently recommend. """

HEADER_RECOMMENDATIONS: dict[str, str] = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

# Minimum acceptable Strict-Transport-Security max-age, in seconds.
# 15768000 = ~6 months. Below this, HSTS offers only weak protection
# since the browser "forgets" to enforce HTTPS too quickly.
MIN_HSTS_MAX_AGE_SECONDS: int = 15_768_000
