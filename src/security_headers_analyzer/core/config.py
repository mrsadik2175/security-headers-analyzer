"""
core.config
~~~~~~~~~~~

Central place for constants and tunables. Keeping these out of the
logic files means Stage 3 (detection) and Stage 5 (scoring) can be
tuned or extended without touching business logic.
"""

from __future__ import annotations

# --- Network behavior (used by the HTTP engine in the Stage 2) ---------------

DEFAULT_TIMEOUT_SECONDS: float =10.0
DEFAULT_USER_AGENT: str ="security-headers-analyzer/0.1  (+passive scanner)"
MAX_REDIRECTS: int =5

# --- Security headers we will check (implemented in Stage 3) -------------
#Kept here now so the architecture is visible from Stage 1, even though
#the detection logic itself lands in a later stage.

REQUIRED_SECURITY_HEADERS: tuple [str, ...]= (
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
    "X-Content-Type-Options" : 10,
    "X-Frame-Options": 15,
    "Referrer-Policy" : 10,
    "Permissions-Policy": 10,
}
