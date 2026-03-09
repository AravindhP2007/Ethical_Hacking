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
    
    # Patterns for sensitive data
    SENSITIVE_PATTERNS = {
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        'password': r'password["\']?\s*[:=]\s*["\']?([^\s"\']+)',
        'secret': r'secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        'token': r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    }
    
    def check_name(self) -> str:
        return "sensitive_data_check"
    
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute sensitive data exposure checks"""
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []
        
        # Test for unencrypted sensitive data
        sensitive_data_result = self._test_sensitive_data_exposure(url, config)
        if sensitive_data_result:
            vulnerabilities.append(sensitive_data_result)
        
        # Test HTTPS enforcement
        https_result = self._test_https_enforcement(url, config)
        if https_result:
            vulnerabilities.append(https_result)
        
        # Test for sensitive data in errors
        error_result = self._test_sensitive_data_in_errors(url, config)
        if error_result:
            vulnerabilities.append(error_result)
        
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
            evidence="No sensitive data exposure detected"
        )
    
    def _test_sensitive_data_exposure(self, url: str, config: ScanConfiguration) -> str:
        """Test for unencrypted sensitive data in responses"""
        if config.dry_run:
            return ""
        
        try:
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            
            # Check for sensitive patterns in response
            for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    logger.warning(f"Sensitive data ({pattern_name}) exposed at {url}")
                    # Don't include the actual sensitive data in the evidence
                    return f"Sensitive data exposed: {pattern_name} pattern detected"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing sensitive data exposure: {e}")
        
        return ""
    
    def _test_https_enforcement(self, url: str, config: ScanConfiguration) -> str:
        """Test if HTTPS is enforced"""
        if config.dry_run:
            return ""
        
        # Check if using HTTP
        if url.startswith('http://'):
            logger.warning(f"Endpoint not using HTTPS: {url}")
            return "HTTPS not enforced - using HTTP"
        
        # Try to access via HTTP
        try:
            http_url = url.replace('https://', 'http://')
            response = requests.get(http_url, headers=config.custom_headers, timeout=10, allow_redirects=False)
            
            # If we get a response without redirect to HTTPS, it's vulnerable
            if response.status_code == 200:
                logger.warning(f"Endpoint accessible via HTTP: {url}")
                return "Endpoint accessible via HTTP without redirect to HTTPS"
        
        except requests.RequestException:
            # If HTTP fails, that's good - HTTPS is enforced
            pass
        
        return ""
    
    def _test_sensitive_data_in_errors(self, url: str, config: ScanConfiguration) -> str:
        """Test for sensitive data in error messages"""
        if config.dry_run:
            return ""
        
        try:
            # Trigger errors with invalid input
            error_triggers = [
                {'id': 'invalid'},
                {'id': -1},
                {'id': '../../etc/passwd'},
            ]
            
            for params in error_triggers:
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)
                
                # Check for sensitive data in error responses
                if response.status_code >= 400:
                    for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                        if re.search(pattern, response.text, re.IGNORECASE):
                            logger.warning(f"Sensitive data in error message at {url}")
                            return f"Sensitive data ({pattern_name}) exposed in error messages"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing sensitive data in errors: {e}")
        
        return ""
