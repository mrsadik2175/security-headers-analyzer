"""
cli

~~~

Command-line entrypoint. Installed as the ``security-headers-analyzer``
console script (see pyproject.toml).

Stage 6 wires in the report generation layer: ``--format`` chooses
console (rich, default) or JSON output, and ``--output`` optionally
writes the report to a file instead of stdout.
"""

from __future__ import annotations

import argparse
import logging

import sys
from security_headers_analyzer import __version__

from security_headers_analyzer.core.scanner import Scanner

from security_headers_analyzer.reporting.console_report import render_console_report
from security_headers_analyzer.reporting.json_report import (
    render_json_report,
    write_json_report,
)

from security_headers_analyzer.utils.logger import setup_logging

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-headers-analyzer",
        description="Analyze the HTTP security headers of a target URL.",
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to scan, e.g. https://example.com",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0)",
    )

    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Report output format (default: console)",
    )

    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Write the report to this file instead of stdout.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging (do not use in shared/CI logs).",
    )

    parser.add_argument(
        "--allow-private",
        action="store_true",
        help=(
            "Allow scanning private/internal/loopback addresses. "
            "For local development only — never use against untrusted input."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose)
    logger.info("Starting scan for %s", args.url)

    scanner = Scanner(
        target_url=args.url,
        timeout=args.timeout,
        allow_private=args.allow_private,
    )
    try:
        result = scanner.run()
    except Exception:  # noqa: BLE001 - top-level CLI boundary, log & exit cleanly
        logger.exception("Unexpected error while scanning %s", args.url)
        return 1
    if args.verbose and result.raw_headers:
        for name, value in sorted(result.raw_headers.items()):
            logger.debug("  %s: %s", name, value)

    if args.format == "json":
        if args.output:
            write_json_report(result, args.output)
            logger.info("JSON report written to %s", args.output)
        else:
            print(render_json_report(result))

    else:
        if args.output:
            # rich can render to any file-like object via a Console
            # bound to that file, so console-format reports can also
            # be saved (e.g. for CI artifact upload) without duplicating
            # the rendering logic.
            from rich.console import Console

            with open(args.output, "w", encoding="utf-8") as f:
                render_console_report(result, console=Console(file=f, width=100))

            logger.info("Console report written to %s", args.output)

        else:
            render_console_report(result)

    return 1 if result.error else 0


if __name__ == "__main__":
    sys.exit(main())
