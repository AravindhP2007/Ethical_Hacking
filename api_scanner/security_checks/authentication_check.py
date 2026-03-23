"""
Authentication vulnerability detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)

# Paths that are expected to require authentication
PROTECTED_PATH_KEYWORDS = ['/user', '/profile', '/account', '/admin', '/dashboard', '/me', '/settings', '/orders']

# Login/auth endpoints where default credential testing makes sense
LOGIN_PATH_KEYWORDS = ['/login', '/signin', '/auth', '/token', '/session']


class AuthenticationCheck(SecurityCheck):
    """Tests for authentication vulnerabilities"""

    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
    ]

    def check_name(self) -> str:
        return "authentication_check"

    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        url = urljoin(config.base_url, endpoint.path)
        path_lower = endpoint.path.lower()
        vulnerabilities = []

        # Only flag missing auth on paths that are expected to be protected
        if any(kw in path_lower for kw in PROTECTED_PATH_KEYWORDS):
            result = self._test_missing_authentication(url, config)
            if result:
                vulnerabilities.append(result)

        # Weak auth: HTTP instead of HTTPS
        if url.startswith('http://'):
            vulnerabilities.append("Credentials transmitted over HTTP (not HTTPS)")

        # Default credentials only on login endpoints
        if any(kw in path_lower for kw in LOGIN_PATH_KEYWORDS):
            result = self._test_default_credentials(url, config)
            if result:
                vulnerabilities.append(result)

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
            evidence="No authentication vulnerabilities detected"
        )

    def _test_missing_authentication(self, url: str, config: ScanConfiguration) -> str:
        if config.dry_run:
            return ""
        try:
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            # Only flag if 200 AND no auth-related headers in the request were needed
            auth_headers = ['Authorization', 'X-Auth-Token', 'X-API-Key']
            request_has_auth = any(h in config.custom_headers for h in auth_headers)
            if response.status_code == 200 and not request_has_auth:
                return "Protected endpoint accessible without authentication"
        except requests.RequestException as e:
            logger.debug(f"Auth check error: {e}")
        return ""

    def _test_default_credentials(self, url: str, config: ScanConfiguration) -> str:
        if config.dry_run:
            return ""
        try:
            for username, password in self.DEFAULT_CREDENTIALS:
                payload = {'username': username, 'password': password}
                response = requests.post(url, json=payload, timeout=5)
                if response.status_code == 200:
                    resp_lower = response.text.lower()
                    # Only flag if response looks like a successful login (token/session returned)
                    if any(kw in resp_lower for kw in ['token', 'access_token', 'session', 'logged in', 'welcome']):
                        return f"Default credentials accepted: {username}:{password}"
        except requests.RequestException as e:
            logger.debug(f"Default creds check error: {e}")
        return ""
