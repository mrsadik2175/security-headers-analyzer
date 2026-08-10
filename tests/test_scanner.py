""" Tests for Scanner.validate_url() and Scanner.fetch_headers().

No real network calls are made - socket resolution and HTTP requests
are mocked so these tests run fast and offline, and so we can
deterministically test SSRF-protection branches (private IPs) without
needing actual internal infrastructure to point at. """


from unittest.mock import MagicMock, patch
import pytest
import requests
from security_headers_analyzer.core.exceptions import InvalidURLError, ScanRequestError
from security_headers_analyzer.core.scanner import Scanner


class TestValidateUrl:

    def test_rejects_non_http_scheme (self):
        scanner=Scanner("ftp://example.com")
        with pytest.raises (InvalidURLError, match = "Unsupported URL scheme" ):

            scanner.validate_url()
    def test_rejects_missing_hostname (self):
        scanner = Scanner ("https:///path-only")

        with pytest.raises (InvalidURLError, match="missing a hostname"):
            scanner.validate_url ()


    @patch ("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_rejects_loopback_address (self, mock_resolve):

        mock_resolve.return_value = "127.0.0.1"

        scanner = Scanner ("http://localhost")

        with pytest.raises (InvalidURLError, match="SSRF protection") :

            scanner.validate_url ()

    @patch ("security_headers_analyzer.core.scanner.socket.gethostbyname")

    def test_rejects_cloud_metadata_ip(self, mock_resolve):

        # 169.254.169.254 is the well-known cloud metadata endpoint -
        # a classic SSRF target that must always be blocked by default.

        mock_resolve.return_value= "169.254.169.254"
        scanner = Scanner("http://metadata.internal")

        with pytest.raises(InvalidURLError, match="SSRF protection"):
            scanner.validate_url()


    @patch ("security_headers_analyzer.core.scanner.socket.gethostbyname")
    def test_allows_private_ip_when_explicitly_enabled(self, mock_resolve):

        mock_resolve.return_value = "127.0.0.1"
        scanner = Scanner("http://localhost", allow_private=True)

        assert scanner.validate_url() is True

    @patch ("security_headers_analyzer.core.scanner.socket.gethostbyname")

    def test_accepts_public_host(self, mock_resolve) :

        mock_resolve.return_value = "93.184.216.34"
        scanner = Scanner ("https://example.com")

        assert scanner.validate_url() is True

    @patch("security_headers_analyzer.core.scanner.socket.gethostbyname")

    def test_unresolvable_hostname_raises(self, mock_resolve):

        import socket
        mock_resolve.side_effect=socket.gaierror("Name or service not known")
        scanner=Scanner ("https://this-domain-does-not-exist.invalid")
        with pytest.raises (InvalidURLError, match="Could not resolve hostname"):
            scanner.validate_url()


class TestFetchHeaders :

    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_returns_headers_as_plain_dict(self, mock_get):

        mock_response = MagicMock ()
        mock_response.headers = {"Content-Type": "text/html","X-Frame-Options": "DENY"}
        mock_response.status_code = 200

        mock_get.return_value = mock_response

        scanner = Scanner("https://example.com")
        headers = scanner.fetch_headers()

        assert headers["X-Frame-Options"]== "DENY"
        assert scanner._last_status_code == 200
        assert isinstance (headers, dict)


    @patch ("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_timeout_raises_scan_request_error (self, mock_get):
        mock_get.side_effect =requests.exceptions.Timeout()
        scanner = Scanner ("https://example.com")
        with pytest.raises (ScanRequestError, match="timed out"):
            scanner.fetch_headers ()

    @patch ("security_headers_analyzer.core.scanner.requests.Session.get")

    def test_connection_error_raises_scan_request_error(self, mock_get):

        mock_get.side_effect = requests.exceptions.ConnectionError()
        scanner =Scanner("https://example.com")
        with pytest.raises(ScanRequestError, match = "Could not connect"):
            scanner.fetch_headers()
    @patch("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_too_many_redirects_raises_scan_request_error(self, mock_get):
        mock_get.side_effect =requests.exceptions.TooManyRedirects()
        scanner = Scanner ("https://example.com")
        with pytest.raises (ScanRequestError, match="Too many redirects"):
            scanner.fetch_headers ()



class TestRunIntegration:

    """Tests Scanner.run() end-to-end with the network layer mocked. """

    @patch ("security_headers_analyzer.core.scanner.socket.gethostbyname")
    @patch ("security_headers_analyzer.core.scanner.requests.Session.get")
    def test_run_populates_raw_headers_on_success(self, mock_get, mock_resolve):
        mock_resolve.return_value = "93.184.216.34"

        mock_response = MagicMock()
        mock_response.headers = {"X-Content-Type-Options": "nosniff" }
        mock_response.status_code = 200

        mock_get.return_value = mock_response

        scanner =Scanner("https://example.com")
        result = scanner.run()
        assert result.error is None
        assert result.status_code == 200
        assert result.raw_headers["X-Content-Type-Options"] == "nosniff"

        
    def test_run_sets_error_on_invalid_url(self):
        scanner = Scanner("ftp://example.com")
        result = scanner.run()

        assert result.error is not None
        assert result.status_code is None
        assert result.raw_headers == {}
