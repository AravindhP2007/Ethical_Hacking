"""
Injection vulnerability detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)


class InjectionCheck(SecurityCheck):
    """Tests for injection vulnerabilities"""
    
    # SQL injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ]
    
    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        "{'$gt': ''}",
        "{'$ne': null}",
        "admin' || '1'=='1",
    ]
    
    # Command injection payloads
    COMMAND_PAYLOADS = [
        "; ls",
        "| whoami",
        "&& cat /etc/passwd",
        "`id`",
    ]
    
    # XML injection payloads
    XML_PAYLOADS = [
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<![CDATA[<script>alert('XSS')</script>]]>",
    ]
    
    def check_name(self) -> str:
        return "injection_check"
    
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute injection vulnerability checks"""
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []
        
        # Test SQL injection
        sql_result = self._test_sql_injection(url, endpoint, config)
        if sql_result:
            vulnerabilities.append(sql_result)
        
        # Test NoSQL injection
        nosql_result = self._test_nosql_injection(url, endpoint, config)
        if nosql_result:
            vulnerabilities.append(nosql_result)
        
        # Test command injection
        cmd_result = self._test_command_injection(url, endpoint, config)
        if cmd_result:
            vulnerabilities.append(cmd_result)
        
        # Test XML injection
        xml_result = self._test_xml_injection(url, endpoint, config)
        if xml_result:
            vulnerabilities.append(xml_result)
        
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
            evidence="No injection vulnerabilities detected"
        )
    
    def _test_sql_injection(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for SQL injection vulnerabilities"""
        if config.dry_run:
            return ""
        
        try:
            for payload in self.SQL_PAYLOADS:
                # Test in query parameters
                params = {'id': payload, 'search': payload}
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)
                
                # Look for SQL error messages
                error_indicators = [
                    'sql', 'mysql', 'postgresql', 'oracle', 'sqlite',
                    'syntax error', 'database error', 'query failed'
                ]
                
                response_lower = response.text.lower()
                for indicator in error_indicators:
                    if indicator in response_lower:
                        logger.warning(f"Possible SQL injection at {url} with payload: {payload}")
                        return f"SQL injection detected with payload: {payload}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing SQL injection: {e}")
        
        return ""
    
    def _test_nosql_injection(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for NoSQL injection vulnerabilities"""
        if config.dry_run:
            return ""
        
        try:
            for payload in self.NOSQL_PAYLOADS:
                params = {'filter': payload}
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)
                
                # Look for NoSQL error messages
                error_indicators = ['mongodb', 'nosql', 'document', 'collection']
                
                response_lower = response.text.lower()
                for indicator in error_indicators:
                    if indicator in response_lower:
                        logger.warning(f"Possible NoSQL injection at {url}")
                        return f"NoSQL injection detected with payload: {payload}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing NoSQL injection: {e}")
        
        return ""
    
    def _test_command_injection(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for command injection vulnerabilities"""
        if config.dry_run:
            return ""
        
        try:
            for payload in self.COMMAND_PAYLOADS:
                params = {'cmd': payload, 'exec': payload}
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)
                
                # Look for command execution indicators
                indicators = ['root:', 'uid=', 'gid=', '/bin/', '/usr/']
                
                for indicator in indicators:
                    if indicator in response.text:
                        logger.warning(f"Possible command injection at {url}")
                        return f"Command injection detected with payload: {payload}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing command injection: {e}")
        
        return ""
    
    def _test_xml_injection(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for XML injection vulnerabilities"""
        if config.dry_run:
            return ""
        
        try:
            for payload in self.XML_PAYLOADS:
                headers = {**config.custom_headers, 'Content-Type': 'application/xml'}
                response = requests.post(url, data=payload, headers=headers, timeout=10)
                
                # Look for XXE indicators
                indicators = ['root:', '/etc/passwd', 'ENTITY']
                
                for indicator in indicators:
                    if indicator in response.text:
                        logger.warning(f"Possible XML injection at {url}")
                        return f"XML injection detected"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing XML injection: {e}")
        
        return ""
