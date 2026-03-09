"""
Access control vulnerability detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)


class AccessControlCheck(SecurityCheck):
    """Tests for broken access control"""
    
    def check_name(self) -> str:
        return "access_control_check"
    
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute access control vulnerability checks"""
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []
        
        # Test for IDOR
        idor_result = self._test_idor(url, endpoint, config)
        if idor_result:
            vulnerabilities.append(idor_result)
        
        # Test for missing function-level access control
        function_level_result = self._test_function_level_access(url, endpoint, config)
        if function_level_result:
            vulnerabilities.append(function_level_result)
        
        # Test for privilege escalation
        privilege_result = self._test_privilege_escalation(url, endpoint, config)
        if privilege_result:
            vulnerabilities.append(privilege_result)
        
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
            evidence="No access control vulnerabilities detected"
        )
    
    def _test_idor(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for Insecure Direct Object References"""
        if config.dry_run:
            return ""
        
        try:
            # Test with different ID values
            test_ids = ['1', '2', '999', 'admin', '../admin']
            
            for test_id in test_ids:
                # Replace ID in path or add as parameter
                test_url = url.replace('{id}', test_id)
                if '{id}' not in url:
                    params = {'id': test_id, 'user_id': test_id}
                    response = requests.get(test_url, params=params, headers=config.custom_headers, timeout=10)
                else:
                    response = requests.get(test_url, headers=config.custom_headers, timeout=10)
                
                # If we get 200 OK, might be vulnerable to IDOR
                if response.status_code == 200 and len(response.text) > 100:
                    logger.warning(f"Possible IDOR vulnerability at {url}")
                    return f"Possible IDOR - accessible with ID: {test_id}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing IDOR: {e}")
        
        return ""
    
    def _test_function_level_access(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for missing function-level access control"""
        if config.dry_run:
            return ""
        
        try:
            # Test admin endpoints without admin credentials
            admin_paths = ['/admin', '/api/admin', '/management', '/config']
            
            for admin_path in admin_paths:
                if admin_path in url.lower():
                    response = requests.get(url, headers=config.custom_headers, timeout=10)
                    
                    if response.status_code == 200:
                        logger.warning(f"Admin endpoint accessible without proper authorization: {url}")
                        return "Admin endpoint accessible without authorization"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing function-level access: {e}")
        
        return ""
    
    def _test_privilege_escalation(self, url: str, endpoint: Endpoint, config: ScanConfiguration) -> str:
        """Test for privilege escalation vulnerabilities"""
        if config.dry_run:
            return ""
        
        try:
            # Test role manipulation
            role_params = [
                {'role': 'admin'},
                {'is_admin': 'true'},
                {'privilege': 'admin'},
                {'user_type': 'admin'}
            ]
            
            for params in role_params:
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)
                
                # Check if role parameter affects response
                if response.status_code == 200 and 'admin' in response.text.lower():
                    logger.warning(f"Possible privilege escalation at {url}")
                    return f"Possible privilege escalation via parameter: {list(params.keys())[0]}"
        
        except requests.RequestException as e:
            logger.debug(f"Error testing privilege escalation: {e}")
        
        return ""
