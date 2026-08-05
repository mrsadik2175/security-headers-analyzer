"""
security-headers-analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~

A passive HTTP security header analysis tool.

This package is intentionally split into small, single responsibility
modules so each project stage (Stage 2: HTTP engine, Stage 3: header
detection, Stage 5: risk scoring, Stage 6: reporting) can be developed
and tested in isolation without touching unrelated code.
"""

__version__ ="0.1.0"
__all__ =["__version__"]
