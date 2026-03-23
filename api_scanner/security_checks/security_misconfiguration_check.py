"""
Security misconfiguration detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult, HttpMethod

logger = logging.getLogger(__name__)

# Only the most critical security headers — reduces noise
CRITICAL_SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'Content-Security-Policy',
]


class SecurityMisconfigurationCheck(SecurityCheck):
    """Tests for security misconfigurations"""

    def check_name(self) -> str:
        return "security_misconfiguration_check"

    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []

        # Test for verbose error messages leaking stack traces / file paths
        verbose_result = self._test_verbose_errors(url, config)
        if verbose_result:
            vulnerabilities.append(verbose_result)

        # Only check security headers on the root/base endpoint to avoid duplicate reports
        if endpoint.path in ['/', '/api', '']:
            headers_result = self._test_security_headers(url, config)
            if headers_result:
                vulnerabilities.append(headers_result)

        # Test for TRACE method (genuinely dangerous — enables XST attacks)
        trace_result = self._test_trace_method(url, config)
        if trace_result:
            vulnerabilities.append(trace_result)

        if vulnerabilities:
            return CheckResult(
                check_name=self.check_name(),
                endpoint=endpoint.path,
                vulnerable=True,
                evidence="; ".join(vulnerabilities)
            )

        return CheckResult(
            check_name=self.check_name(),
            endpoint=endpoint.path,
            vulnerable=False,
            evidence="No security misconfigurations detected"
        )

    def _test_verbose_errors(self, url: str, config: ScanConfiguration) -> str:
        """Test for verbose error messages that leak implementation details"""
        if config.dry_run:
            return ""
        try:
            response = requests.get(url, params={'id': 'INVALID_TEST_VALUE_XYZ'}, headers=config.custom_headers, timeout=10)
            # Only flag on error responses (4xx/5xx) that contain stack trace indicators
            if response.status_code >= 400:
                stack_trace_indicators = [
                    'traceback', 'stack trace', 'at line ', 'file "/', 'file \'/',
                    'c:\\users\\', 'c:\\inetpub', '/var/www/', '/home/',
                    'syntaxerror', 'nameerror', 'typeerror', 'valueerror',
                ]
                response_lower = response.text.lower()
                for indicator in stack_trace_indicators:
                    if indicator in response_lower:
                        return "Verbose error messages leak implementation details (stack trace/file paths exposed)"
        except requests.RequestException as e:
            logger.debug(f"Error testing verbose errors: {e}")
        return ""

    def _test_security_headers(self, url: str, config: ScanConfiguration) -> str:
        """Test for missing critical security headers"""
        if config.dry_run:
            return ""
        try:
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            if response.status_code not in [200, 301, 302]:
                return ""
            missing = [h for h in CRITICAL_SECURITY_HEADERS if h not in response.headers]
            if len(missing) >= 2:  # Only flag if multiple critical headers are missing
                return f"Missing critical security headers: {', '.join(missing)}"
        except requests.RequestException as e:
            logger.debug(f"Error testing security headers: {e}")
        return ""

    def _test_trace_method(self, url: str, config: ScanConfiguration) -> str:
        """Test for TRACE method (enables Cross-Site Tracing attacks)"""
        if config.dry_run:
            return ""
        try:
            response = requests.request('TRACE', url, timeout=5)
            # TRACE is vulnerable if server echoes back the request body
            if response.status_code == 200 and 'TRACE' in response.text.upper():
                return "TRACE method enabled — vulnerable to Cross-Site Tracing (XST)"
        except requests.RequestException:
            pass
        return ""
