"""
core.scanner

~~~~~~~~~~~~


The orchestrator class that ties the whole pipeline together:
    URL validation -> HTTP request -> header detection -> risk scoring -> report

Stage 2 implements ``validate_url()`` and ``fetch_headers()`` for real.
``detect_headers()`` and ``score_risk()`` remain stubs until Stages 3
and 5. ``run()`` is partially wired: it validates + fetches now, and
returns a ScanResult with raw headers attached, ready for Stage 3 to
consume. """


from __future__ import annotations
import ipaddress
import logging
import socket
from urllib.parse import urlparse
import requests
from security_headers_analyzer.core.config import  (

    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_USER_AGENT,

    MAX_REDIRECTS,
)

from security_headers_analyzer.core.exceptions import InvalidURLError, ScanRequestError
from security_headers_analyzer.core.models import ScanResult

logger= logging.getLogger (__name__)
ALLOWED_SCHEMES={"http", "https"}


class Scanner:

    """Coordinates a single-URL security header scan. """
    def __init__ (
            
        self,
        target_url : str,
        timeout: float| None= None,
        allow_private: bool =False,

    ) ->None:
        self.target_url = target_url
        self.timeout= timeout or DEFAULT_TIMEOUT_SECONDS
        #  SSRF guard toggle: only meant for local/dev testing against
        # e.g http://localhost:8000. Never enable this in a shared
        # or production deployment of the tool.

        self.allow_private = allow_private
        self._last_status_code: int | None= None
        logger.debug ("Scanner initialized for target=%s", self.target_url)

    # ---- Stage 2: URL validation ---------------------------------------------------
    def validate_url(self) ->bool:
        """Validate ``self.target_url`` is a safe, well-formed HTTP(S) URL.

        Two layer of validation:
          1. Structural — must be http(s), must have a hostname.
          2. Network (SSRF guard) — the hostname must not resolve to a
             private, loopback, link-local, or otherwise reserved IP,
             unless ``allow_private`` was explicitly set.

        Raises:
            InvalidURLError: if either check fails.
          """
        
        parsed=urlparse(self.target_url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise InvalidURLError (
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
        ``http://localhost:6379`` (internal services). """

        try:
            resolved_ip = socket.gethostbyname (hostname)
        except socket.gaierror as exc:
            raise InvalidURLError (f"Could not resolve hostname '{hostname}': {exc}") from exc

        ip_obj=ipaddress.ip_address(resolved_ip)

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
    def fetch_headers(self) ->dict[str, str]:
        """Perform the HTTP request and return raw response headers.
        Uses a dedicated ``requests.Session`` with a capped redirect
        count and an explicit User-Agent (so the tool identifies
        itself honestly rather than spoofing a browser).  """


        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        try:
            response = session.get(
                self.target_url,
                timeout =self.timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=True,
            )
        except requests.exceptions.Timeout as exc:
            raise ScanRequestError(f"Request to {self.target_url} timed out after {self.timeout}s") from exc
        except requests.exceptions.TooManyRedirects as exc:

            raise ScanRequestError(f"Too many redirects (limit={MAX_REDIRECTS}) for {self.target_url}") from exc
        except requests.exceptions.SSLError as exc:
            raise ScanRequestError(f"TLS/SSL error connecting to {self.target_url}: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:

            raise ScanRequestError(f"Could not connect to {self.target_url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise ScanRequestError(f"Request to {self.target_url} failed: {exc}") from exc
        self._last_status_code= response.status_code
        # requests.Response.headers is a case-insensitive dict already;
        #  cast to a plain dict for a stable, serializable return type.

        return dict (response.headers)

    # -- Stubs for later stages -----------------------------------------------

    def detect_headers (self, raw_headers: dict[str, str]) -> list:
        """Compare raw headers against the expected security header set.

        Implemented in Stage 3.

        """
        raise NotImplementedError ("Header detection lands in Stage 3.")

    def score_risk(self, findings: list)-> str:
        """Compute an overall risk level from individual findings.

        Implemented in Stage 5.
        """

        raise NotImplementedError("Risk scoring lands in Stage 5.")

    # -- Orchestration (partially wired) ----------------------------------

    def run(self)-> ScanResult:
        """Execute the pipeline as far as it's implemented.

        
        Currently: validate -> fetch. The returned ScanResult carries
        ``raw_headers`` and ``status_code`` populated, with detection
        and scoring left for Stages 3-5 to fill in ``findings`` and
        ``overall_risk``. """

        result = ScanResult(target_url=self.target_url)


        try:

            self.validate_url ()
            raw_headers=self.fetch_headers ()
        except (InvalidURLError, ScanRequestError) as exc:
            result.error= str(exc)
            logger.error ("Scan failed for %s: %s", self.target_url, exc)

            return result

        result.status_code = self._last_status_code
        result.raw_headers = raw_headers

        logger.info (
            "Fetched %d response headers from %s (HTTP %s)",
            len (raw_headers),
            self.target_url,
            result.status_code,
        )
        
        # Header detection & risk scoring land in Stages 3-5.

        return result
    
# End for stage 2.
