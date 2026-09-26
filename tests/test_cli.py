""" Tests for cli.main() - argument parsing and end-to-end wiring, with
Scanner.run() mocked so no real network calls happen.

This closes a coverage gap surfaced while adding pytest-cov in
Stage 7: earlier stages tested Scanner and the reporting modules in
isolation, but never the CLI entrypoint that wires them together. """

import json
import pytest
from security_headers_analyzer.cli import build_parser, main
from security_headers_analyzer.core.models import HeaderFinding, HeaderStatus, RiskLevel, ScanResult

def _successful_result() -> ScanResult:
    result = ScanResult(target_url="https://example.com", status_code=200)
    result.findings = [
        HeaderFinding("X-Content-Type-Options", HeaderStatus.PRESENT, value="nosniff", severity=RiskLevel.INFO)
    ]

    result.overall_risk = RiskLevel.LOW
    result.security_score = 95.0
    result.duration_seconds = 0.123

    return result


def _failed_result() -> ScanResult:
    result = ScanResult(target_url="ftp://bad-url")
    result.error = "Unsupported URL scheme 'ftp'."
    result.duration_seconds = 0.001

    return result


class TestBuildParser:
    def test_url_is_required(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com"])
        assert args.timeout == 10.0
        assert args.format == "console"
        assert args.output is None
        assert args.verbose is False
        assert args.allow_private is False

    def test_format_rejects_invalid_choice(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--url", "https://example.com", "--format", "xml"])



class TestMain:
    def test_returns_0_on_successful_scan(self, monkeypatch, capsys):
        monkeypatch.setattr("security_headers_analyzer.cli.Scanner.run", lambda self: _successful_result())
        exit_code = main(["--url", "https://example.com"])
        assert exit_code == 0

    def test_returns_1_on_scan_error(self, monkeypatch):
        monkeypatch.setattr("security_headers_analyzer.cli.Scanner.run", lambda self: _failed_result())
        exit_code = main(["--url", "ftp://bad-url"])
        assert exit_code == 1

    def test_returns_1_on_unexpected_exception(self, monkeypatch):
        def _boom(self):
            raise RuntimeError("something broke")

        monkeypatch.setattr("security_headers_analyzer.cli.Scanner.run", _boom)
        exit_code = main(["--url", "https://example.com"])
        assert exit_code == 1

    def test_json_format_prints_valid_json_to_stdout(self, monkeypatch, capsys):
        monkeypatch.setattr("security_headers_analyzer.cli.Scanner.run", lambda self: _successful_result())
        main(["--url", "https://example.com", "--format", "json"])

        captured = capsys.readouterr()
        # stdout should contain a JSON blob we can parse - log lines go
        # to stderr via logging, so stdout should be clean JSON.
        parsed = json.loads(captured.out)
        assert parsed["target_url"] == "https://example.com"
        assert parsed["overall_risk"] == "low"

    def test_json_format_writes_to_output_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr("security_headers_analyzer.cli.Scanner.run", lambda self: _successful_result())
        output_path = tmp_path / "report.json"
        exit_code = main(["--url", "https://example.com", "--format", "json", "--output", str(output_path)])

        assert exit_code == 0
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["target_url"] == "https://example.com"

    def test_console_format_writes_to_output_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr("security_headers_analyzer.cli.Scanner.run", lambda self: _successful_result())
        output_path = tmp_path / "report.txt"
        exit_code = main(["--url", "https://example.com", "--output", str(output_path)])
        assert exit_code == 0
        content = output_path.read_text(encoding="utf-8")
        assert "example.com" in content
