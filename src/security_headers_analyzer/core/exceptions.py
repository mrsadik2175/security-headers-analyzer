"""
core.exceptions
~~~~~~~~~~~~~~~~

Custom exception for the scanning pipeline.


Using specific exception types (instead of bare ValueError/Exception)
lets callers (CLI, and later a possible API layer) distinguish between
"the user gave us a bad/unsafe URL" and "the network request itself
failed" - these need different handling and different messages. """


from __future__ import annotations


class ScannerError (Exception) :
    """Base class for all scanner-related errors."""


class InvalidURLError (ScannerError):

    """Raised when a target URL is malformed, uses a disallowed scheme,
    or resolves to a private/internal address that must not be scanned.
    """


class ScanRequestError (ScannerError):
    """ Raised when the HTTP request to the target fails
    (timeout, connection error, TLS error, too many redirects, etc.). """
