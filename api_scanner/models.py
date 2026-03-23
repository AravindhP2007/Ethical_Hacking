"""
Data models for the API Vulnerability Scanner.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime, timedelta


class HttpMethod(Enum):
    """HTTP methods supported by endpoints"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Parameter:
    """API endpoint parameter"""
    name: str
    location: str  # query, header, body, path
    type: str
    required: bool


@dataclass
class AuthCredentials:
    """Authentication credentials"""
    type: str  # bearer, basic, api_key, oauth2
    credentials: Dict[str, str]


@dataclass
class HttpResponse:
    """HTTP response data"""
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time_ms: int


@dataclass
class ValidationResult:
    """Configuration validation result"""
    valid: bool
    errors: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    """API endpoint representation"""
    path: str
    methods: List[HttpMethod]
    parameters: List[Parameter] = field(default_factory=list)
    authentication_required: bool = False


@dataclass
class ScanConfiguration:
    """Configuration for a vulnerability scan"""
    base_url: str
    endpoints: Optional[List[str]] = None
    excluded_endpoints: List[str] = field(default_factory=list)
    security_checks: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    auth_credentials: Optional[AuthCredentials] = None
    severity_threshold: SeverityLevel = SeverityLevel.INFO
    dry_run: bool = False
    read_only: bool = True
    request_throttle_ms: int = 100
    verbose_logging: bool = False


@dataclass
class CheckResult:
    """Result from executing a security check"""
    check_name: str
    endpoint: str
    vulnerable: bool
    evidence: str
    raw_response: Optional[HttpResponse] = None


@dataclass
class Vulnerability:
    """Detected vulnerability"""
    type: str
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    endpoint: str
    evidence: str
    check_result: Optional[CheckResult] = None


@dataclass
class RemediationGuidance:
    """Remediation instructions for a vulnerability"""
    steps: List[str]
    references: List[str]
    owasp_mapping: str


@dataclass
class Alert:
    """Security alert for a detected vulnerability"""
    id: str
    vulnerability: Vulnerability
    remediation: RemediationGuidance
    timestamp: datetime
    requires_manual_verification: bool = False


@dataclass
class ScanReport:
    """Complete scan report"""
    scan_id: str
    timestamp: datetime
    configuration: ScanConfiguration
    endpoints_scanned: int
    checks_performed: int
    alerts: List[Alert]
    scan_duration: timedelta


@dataclass
class ScanProgress:
    """Current scan progress"""
    total_checks: int
    completed_checks: int
    current_endpoint: str
    current_check: str
    estimated_remaining_seconds: int


@dataclass
class FalsePositiveEntry:
    """Record of a false positive"""
    vulnerability_type: str
    endpoint: str
    evidence_hash: str
    marked_by: str
    timestamp: datetime


# Vulnerability severity mappings
VULNERABILITY_SEVERITY_MAP = {
    "sql_injection": SeverityLevel.CRITICAL,
    "nosql_injection": SeverityLevel.CRITICAL,
    "command_injection": SeverityLevel.CRITICAL,
    "xml_injection": SeverityLevel.CRITICAL,
    "authentication_bypass": SeverityLevel.HIGH,
    "weak_authentication": SeverityLevel.HIGH,
    "broken_access_control": SeverityLevel.HIGH,
    "idor": SeverityLevel.HIGH,
    "privilege_escalation": SeverityLevel.HIGH,
    "sensitive_data_exposure": SeverityLevel.HIGH,
    "missing_https": SeverityLevel.HIGH,
    "exposed_credentials": SeverityLevel.HIGH,
    "missing_rate_limit": SeverityLevel.MEDIUM,
    "verbose_errors": SeverityLevel.MEDIUM,
    "missing_security_headers": SeverityLevel.MEDIUM,
    "unnecessary_http_methods": SeverityLevel.MEDIUM,
}

# OWASP API Security Top 10 mappings
OWASP_API_MAPPING = {
    "authentication_bypass": "API2:2023 Broken Authentication",
    "weak_authentication": "API2:2023 Broken Authentication",
    "broken_access_control": "API1:2023 Broken Object Level Authorization",
    "idor": "API1:2023 Broken Object Level Authorization",
    "privilege_escalation": "API5:2023 Broken Function Level Authorization",
    "sql_injection": "API8:2023 Security Misconfiguration",
    "nosql_injection": "API8:2023 Security Misconfiguration",
    "command_injection": "API8:2023 Security Misconfiguration",
    "sensitive_data_exposure": "API3:2023 Broken Object Property Level Authorization",
    "missing_rate_limit": "API4:2023 Unrestricted Resource Consumption",
    "missing_https": "API8:2023 Security Misconfiguration",
    "exposed_credentials": "API2:2023 Broken Authentication",
    "verbose_errors": "API8:2023 Security Misconfiguration",
    "missing_security_headers": "API8:2023 Security Misconfiguration",
}
