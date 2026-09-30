"""
utils.logger
~~~~~~~~~~~~~

Centralized logging configuration.

Security note: this logger deliberately never logs full response
bodies or raw request headers at INFO level or above, to avoid
accidentally leaking sensitive data (e.g. Set-Cookie values) into log
files or CI output. Verbose header dumps are only emitted at DEBUG,
which should never be enabled in a shared/CI environment by default.

Stream note (fixed in Stage 8): logs are written to STDERR, not
STDOUT. This was a real bug found during production packaging
verification - with logs on stdout, ``--format json`` output (meant
to be piped into ``jq`` or another tool) got interleaved with log
lines and produced invalid JSON. Diagnostic output and machine-
readable data output must go to separate streams.
"""

from __future__ import annotations

import logging
import sys


def setup_logging(verbose: bool = False) -> None:
    """Configure root logging for the whole application.

    Args:
        verbose: if True, enable DEBUG-level output. Should only be
            used locally by a developer, never in CI/shared logs,
            since DEBUG may include raw header values.
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,  # ensure re-running setup (e.g. across test runs) actually rebinds the stream
    )
