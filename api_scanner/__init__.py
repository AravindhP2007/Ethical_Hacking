"""
API Vulnerability Scanner
An ethical hacking tool for detecting security vulnerabilities in REST APIs.
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .scanner import VulnerabilityScanner
from .models import (
    ScanConfiguration,
    Endpoint,
    Vulnerability,
    Alert,
    ScanReport,
    SeverityLevel,
)

__all__ = [
    "VulnerabilityScanner",
    "ScanConfiguration",
    "Endpoint",
    "Vulnerability",
    "Alert",
    "ScanReport",
    "SeverityLevel",
]
