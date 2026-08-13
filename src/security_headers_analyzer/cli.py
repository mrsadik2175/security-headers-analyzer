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
        prog= "security-headers-analyzer",
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
        "--allow-private",

        action="store_true",
        help=(
            "Allow scanning private/internal/loopback addresses. "
            "For local development only - never use against untrusted input."
        ),
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

    scanner = Scanner(
        target_url =args.url,
        timeout=args.timeout,
        allow_private= args.allow_private,
    )

    try:
        result= scanner.run()
    except Exception: # noqa: BLE001 - top-level CLI boundary, log & exit cleanly
        logger.exception ("Unexpected error while scanning %s", args.url)
        return 1
    if result.error:
        logger.error("Scan failed: %s", result.error)
        return 1


    logger.info (
        "Scan complete. HTTP %s, %d response headers fetched.",
        result.status_code,

        len(result.raw_headers),
    )

    if args.verbose:
        for name, value in sorted (result.raw_headers.items ()):
            logger.debug("  %s: %s", name, value)

    if result.findings:

        present =[f for f in result.findings if f.status.value == "present"]
        missing =[f for f in result.findings if f.status.value == "missing"]
        logger.info(
            "Security headers: %d present, %d missing (of %d checked)",
            len(present),

            len (missing),
            len(result.findings),
        )
        for finding in result.findings :
            marker = "✓" if finding.status.value == "present" else "✗"
            print(f"  {marker} {finding.header_name}: {finding.status.value}")

    # Missing-header analysis, risk scoring, and report generation
    # land in Stages 4-6 -- for now, present/missing status is all we surface.

    return 0

if __name__ == "__main__":
    sys.exit(main())