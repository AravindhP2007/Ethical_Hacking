"""
Access control vulnerability detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)

# Paths that suggest admin/privileged access
ADMIN_PATH_KEYWORDS = ['/admin', '/management', '/config', '/superuser', '/root']


class AccessControlCheck(SecurityCheck):
    """Tests for broken access control"""

    def check_name(self) -> str:
        return "access_control_check"

    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        url = urljoin(config.base_url, endpoint.path)
        path_lower = endpoint.path.lower()
        vulnerabilities = []

        # Only test IDOR on paths that look like resource endpoints (contain /users, /orders, /items etc.)
        resource_keywords = ['/user', '/order', '/item', '/product', '/account', '/profile', '/record']
        if any(kw in path_lower for kw in resource_keywords):
            idor_result = self._test_idor(url, endpoint, config)
            if idor_result:
                vulnerabilities.append(idor_result)

        # Only test admin access on paths that look like admin endpoints
        if any(kw in path_lower for kw in ADMIN_PATH_KEYWORDS):
            function_level_result = self._test_function_level_access(url, config)
            if function_level_result:
                vulnerabilities.append(function_level_result)

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
            evidence="No access control vulnerabilities detected"
        )

    def _test_idor(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for Insecure Direct Object References"""
        if config.dry_run:
            return ""
        try:
            # Get baseline response first
            baseline = requests.get(url, headers=config.custom_headers, timeout=10)
            if baseline.status_code != 200:
                return ""

            # Try accessing with a different user ID — if we get different data, possible IDOR
            test_ids = ['999999', '0', '-1']
            for test_id in test_ids:
                params = {'id': test_id, 'user_id': test_id}
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)
                # Only flag if: 200 response AND response body is substantially different from baseline
                # AND response contains user-like data fields
                if response.status_code == 200:
                    data_keywords = ['"id"', '"email"', '"username"', '"name"', '"user"']
                    if any(kw in response.text for kw in data_keywords):
                        if response.text != baseline.text:
                            return f"Possible IDOR - different user data returned with ID: {test_id}"
        except requests.RequestException as e:
            logger.debug(f"Error testing IDOR: {e}")
        return ""

    def _test_function_level_access(self, url: str, config: ScanConfiguration) -> str:
        """Test for missing function-level access control on admin endpoints"""
        if config.dry_run:
            return ""
        try:
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            # Only flag if admin endpoint returns 200 with actual content (not a login redirect)
            if response.status_code == 200 and len(response.text) > 200:
                # Make sure it's not just a login page
                login_indicators = ['login', 'sign in', 'password', 'unauthorized']
                if not any(kw in response.text.lower() for kw in login_indicators):
                    return "Admin endpoint accessible without authorization"
        except requests.RequestException as e:
            logger.debug(f"Error testing function-level access: {e}")
        return ""
