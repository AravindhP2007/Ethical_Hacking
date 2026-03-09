"""
Security misconfiguration detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult, HttpMethod

logger = logging.getLogger(__name__)


class SecurityMisconfigurationCheck(SecurityCheck):
    """Tests for security misconfigurations"""
    
    # Security headers that should be present
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy',
        'X-XSS-Protection',
    ]
    
    def check_name(self) -> str:
        return "security_misconfiguration_check"
    
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute security misconfiguration checks"""
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []
        
        # Test for verbose errors
        verbose_errors_result = self._test_verbose_errors(url, config)
        if verbose_errors_result:
            vulnerabilities.append(verbose_errors_result)
        
        # Test for missing security headers
        headers_result = self._test_security_headers(url, config)
        if headers_result:
            vulnerabilities.append(headers_result)
        
        # Test for unnecessary HTTP methods
        methods_result = self._test_unnecessary_methods(url, endpoint, config)
        if methods_result:
            vulnerabilities.append(methods_result)
        
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
            evidence="No security misconfigurations detected"
        )
    
    def _test_verbose_errors(self, url: str, config: ScanConfiguration) -> str:
        """Test for verbose error messages"""
        if config.dry_run:
            return ""
        
        try:
            # Trigger errors with invalid input
            response = requests.get(url, params={'id': 'invalid'}, headers=config.custom_headers, timeout=10)
            
            # Look for verbose error indicators
            verbose_indicators = [
                'stack trace',
                'traceback',
                'exception',
                'at line',
                'file path',
                'c:\\',
                '/var/www',
                '/home/',
                'mysql',
                'postgresql',
                'mongodb',
            ]
            
            response_lower = response.text.lower()
            for indicator in verbose_indicators:
                if indicator in response_lower:
                    logger.warning(f"Verbose error messages at {url}")
                    return f"Verbose error messages leak implementation details"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing verbose errors: {e}")
        
        return ""
    
    def _test_security_headers(self, url: str, config: ScanConfiguration) -> str:
        """Test for missing security headers"""
        if config.dry_run:
            return ""
        
        try:
            response = requests.get(url, headers=config.custom_headers, timeout=10)
            
            missing_headers = []
            for header in self.SECURITY_HEADERS:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                logger.warning(f"Missing security headers at {url}: {missing_headers}")
                return f"Missing security headers: {', '.join(missing_headers)}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing security headers: {e}")
        
        return ""
    
    def _test_unnecessary_methods(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for unnecessary HTTP methods"""
        if config.dry_run:
            return ""
        
        try:
            # Test for dangerous methods that shouldn't be enabled
            dangerous_methods = [HttpMethod.TRACE, HttpMethod.OPTIONS]
            unnecessary_methods = []
            
            for method in dangerous_methods:
                try:
                    response = requests.request(method.value, url, timeout=5)
                    if response.status_code != 405:  # 405 = Method Not Allowed
                        unnecessary_methods.append(method.value)
                except requests.RequestException:
                    pass
            
            # Also check if DELETE is enabled on non-resource endpoints
            if HttpMethod.DELETE not in endpoint.methods:
                try:
                    response = requests.delete(url, timeout=5)
                    if response.status_code != 405:
                        unnecessary_methods.append('DELETE')
                except requests.RequestException:
                    pass
            
            if unnecessary_methods:
                logger.warning(f"Unnecessary HTTP methods at {url}: {unnecessary_methods}")
                return f"Unnecessary HTTP methods enabled: {', '.join(unnecessary_methods)}"
        
        except Exception as e:
            logger.debug(f"Error testing unnecessary methods: {e}")
        
        return ""
