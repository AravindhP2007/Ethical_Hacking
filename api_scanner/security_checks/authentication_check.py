"""
Authentication vulnerability detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult, HttpResponse

logger = logging.getLogger(__name__)


class AuthenticationCheck(SecurityCheck):
    """Tests for authentication vulnerabilities"""
    
    # Common default credentials to test
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
        ('user', 'user'),
        ('test', 'test'),
    ]
    
    def check_name(self) -> str:
        return "authentication_check"
    
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute authentication vulnerability checks"""
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []
        
        # Test 1: Missing authentication
        missing_auth_result = self._test_missing_authentication(url, config)
        if missing_auth_result:
            vulnerabilities.append(missing_auth_result)
        
        # Test 2: Weak authentication schemes
        weak_auth_result = self._test_weak_authentication(url, config)
        if weak_auth_result:
            vulnerabilities.append(weak_auth_result)
        
        # Test 3: Default credentials
        default_creds_result = self._test_default_credentials(url, config)
        if default_creds_result:
            vulnerabilities.append(default_creds_result)
        
        # Combine results
        if vulnerabilities:
            evidence = "; ".join(vulnerabilities)
            return CheckResult(
                check_name=self.check_name(),
                endpoint=endpoint.path,
                vulnerable=True,
                evidence=evidence
            )
        
        return CheckResult(
            check_name=self.check_name(),
            endpoint=endpoint.path,
            vulnerable=False,
            evidence="No authentication vulnerabilities detected"
        )
    
    def _test_missing_authentication(self, url: str, config: ScanConfiguration) -> str:
        """Test for missing authentication on protected endpoints"""
        if config.dry_run:
            return ""
        
        try:
            # Try to access without authentication
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            
            # If we get 200 OK without auth, it might be vulnerable
            if response.status_code == 200:
                logger.warning(f"Endpoint {url} accessible without authentication")
                return "Endpoint accessible without authentication (HTTP 200)"
            
        except requests.RequestException as e:
            logger.debug(f"Error testing missing authentication: {e}")
        
        return ""
    
    def _test_weak_authentication(self, url: str, config: ScanConfiguration) -> str:
        """Test for weak authentication schemes"""
        if config.dry_run:
            return ""
        
        try:
            # Check if using HTTP instead of HTTPS
            if url.startswith('http://'):
                return "Using HTTP instead of HTTPS - credentials transmitted in cleartext"
            
            # Try basic auth with empty credentials
            response = requests.get(url, auth=('', ''), timeout=10)
            if response.status_code == 200:
                return "Accepts empty credentials"
            
        except requests.RequestException as e:
            logger.debug(f"Error testing weak authentication: {e}")
        
        return ""
    
    def _test_default_credentials(self, url: str, config: ScanConfiguration) -> str:
        """Test for default credentials"""
        if config.dry_run or not config.read_only:
            return ""
        
        try:
            for username, password in self.DEFAULT_CREDENTIALS:
                response = requests.get(url, auth=(username, password), timeout=5)
                if response.status_code == 200:
                    logger.warning(f"Default credentials work: {username}:{password}")
                    return f"Default credentials accepted: {username}:{password}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing default credentials: {e}")
        
        return ""
