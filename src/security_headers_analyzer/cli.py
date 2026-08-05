"""
cli

~~~

Command-line entrypoint. Installed as the ``security-headers-analyzer``
console script (see pyproject.toml).

Stage 1: argument parsing + wiring only. Actual scanning is stubbed
until Scanner.run() is implemented across Stages 2-5.
"""

from __future__ import annotations

import argparse
import logging

import sys
from security_headers_analyzer import __version__
from security_headers_analyzer.core.scanner import Scanner

from security_headers_analyzer.utils.logger import setup_logging

logger=logging.getLogger (__name__)


def build_parser()-> argparse.ArgumentParser:
    parser =argparse.ArgumentParser(
        prog="security-headers-analyzer",
        description= "Analyze the HTTP security headers of a target URL.",
    )
    parser.add_argument (
        "--url",
        required=True,
        help="Target URL to scan, e.g. https://example.com",
    )
    parser.add_argument (
        "--timeout",
        type= float,
        default =10.0,
        help = "Request timeout in seconds (default: 10.0)",
    )
    parser.add_argument (
        "--verbose",
        action ="store_true",
        help ="Enable debug logging (do not use in shared/CI logs).",
    )
    parser.add_argument (
        "--version",
        action = "version",
        version =f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None)-> int:
    parser= build_parser()
    args = parser.parse_args(argv)

    setup_logging (verbose=args.verbose)
    logger.info ("Starting scan for %s", args.url)

    scanner =Scanner(target_url=args.url, timeout=args.timeout)
    try:

        scanner.run()
    except NotImplementedError as exc:

        # Expected at this stage - the scanning pipeline isn't wired
        # up yet. Fails loudly and clearly instead of pretending to work.
        logger.error("Feature not available yet: %s", exc)
        return 1
    except Exception:  # noqa: BLE001 - top-level CLI boundary, log & exit cleanly

        logger.exception("Unexpected error while scanning %s", args.url)

        return 1

    return 0



if __name__ == "__main__":
    sys.exit(main())
