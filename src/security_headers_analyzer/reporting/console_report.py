"""

reporting.console_report
~~~~~~~~~~~~~~~~~~~~~~~~~

Human-readable terminal report using ``rich`` - a colored summary
panel (target, HTTP status, score, overall risk) followed by a table
of per-header findings with severity and recommendations."""

from __future__ import annotations
from rich.console import Console
from rich.panel import Panel

from rich.table import Table
from security_headers_analyzer.core.models import ScanResult

# Consistent color mapping used across both the summary panel and the
# per-finding severity column, so "red" always means the same thing
# throughout a single report.


_RISK_COLORS: dict[str, str] = {
    "info": "dim",
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

_STATUS_ICONS: dict[str, str] = {
    "present": "✓",
    "missing": "✗",
    "misconfigured": "⚠",
}
_STATUS_COLORS: dict[str, str] = {
    "present": "green",
    "missing": "red",
    "misconfigured": "yellow",
}


def render_console_report(result: ScanResult, console: Console | None = None) -> None:
    """Print a formatted security header report to the terminal.

    Args:
        result: the completed scan to report on.
        console: an optional rich Console to print to (useful for
            tests, which can pass a Console bound to an in-memory
            buffer instead of real stdout).
    """

    console = console or Console()

    if result.error:
        console.print(
            Panel(
                f"[bold red]Scan failed:[/bold red] {result.error}",
                title=result.target_url,
                border_style="red",
            )
        )
        return

    risk_value = result.overall_risk.value

    risk_color = _RISK_COLORS.get(risk_value, "white")

    summary = (
        f"[bold]{result.target_url}[/bold]\n"
        f"HTTP {result.status_code}   "
        f"Score: [bold {risk_color}]{result.security_score}/100[/bold {risk_color}]   "
        f"Risk: [bold {risk_color}]{risk_value.upper()}[/bold {risk_color}]"
    )

    console.print(Panel(summary, title="Security Header Scan", border_style=risk_color))

    if not result.findings:
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Header", no_wrap=True)
    table.add_column("Status", no_wrap=True)

    table.add_column("Severity", no_wrap=True)
    table.add_column("Recommendation")

    for finding in result.findings:
        status_value = finding.status.value
        icon = _STATUS_ICONS.get(status_value, "?")
        status_color = _STATUS_COLORS.get(status_value, "white")
        severity_value = finding.severity.value
        severity_cell = (
            "-"
            if severity_value == "info"
            else f"[{_RISK_COLORS.get(severity_value, 'white')}]{severity_value}[/]"
        )
        table.add_row(
            finding.header_name,
            f"[{status_color}]{icon} {status_value}[/{status_color}]",
            severity_cell,
            finding.recommendation or "-",
        )

    console.print(table)
