"""
Sensitive data exposure detection.
"""

import logging
import re
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)


class SensitiveDataCheck(SecurityCheck):
    """Tests for sensitive data exposure"""

    # High-confidence patterns only — avoids false positives from common words
    SENSITIVE_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'api_key_in_response': r'"api[_-]?key"\s*:\s*"([a-zA-Z0-9_\-]{32,})"',
        'secret_in_response': r'"(secret|client_secret)"\s*:\s*"([a-zA-Z0-9_\-]{20,})"',
        'password_in_response': r'"password"\s*:\s*"([^"]{4,})"',
        'credit_card': r'\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b',  # Visa/MC patterns
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    }

    def check_name(self) -> str:
        return "sensitive_data_check"

    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []

        # Check for sensitive data patterns in response body
        data_result = self._test_sensitive_data_exposure(url, config)
        if data_result:
            vulnerabilities.append(data_result)

        # Check HTTPS enforcement (only meaningful for HTTP URLs)
        https_result = self._test_https_enforcement(url, config)
        if https_result:
            vulnerabilities.append(https_result)

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
            evidence="No sensitive data exposure detected"
        )

    def _test_sensitive_data_exposure(self, url: str, config: ScanConfiguration) -> str:
        """Test for sensitive data patterns in API responses"""
        if config.dry_run:
            return ""
        try:
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            if response.status_code != 200:
                return ""

            for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                if re.search(pattern, response.text, re.IGNORECASE):
                    logger.warning(f"Sensitive data ({pattern_name}) found at {url}")
                    return f"Sensitive data exposed in response: {pattern_name.replace('_', ' ')}"
        except requests.RequestException as e:
            logger.debug(f"Error testing sensitive data exposure: {e}")
        return ""

    def _test_https_enforcement(self, url: str, config: ScanConfiguration) -> str:
        """Test if the API is served over HTTP instead of HTTPS"""
        if config.dry_run:
            return ""

        # Direct HTTP usage is a clear finding
        if url.startswith('http://'):
            return "API served over HTTP — data transmitted without encryption"

        # For HTTPS URLs, check if HTTP version also responds (no redirect)
        try:
            http_url = url.replace('https://', 'http://', 1)
            response = requests.get(http_url, headers=config.custom_headers, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                return "API accessible via HTTP without redirect to HTTPS — encryption not enforced"
        except requests.RequestException:
            pass  # HTTP fails = HTTPS is enforced, no issue

        return ""
