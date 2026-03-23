"""
Security Check Engine for orchestrating vulnerability scans.
"""

import logging
import time
from typing import List
from .models import Endpoint, ScanConfiguration, CheckResult
from .security_checks.base import SecurityCheck

logger = logging.getLogger(__name__)


class SecurityCheckEngine:
    """Orchestrates execution of security checks"""
    
    def __init__(self, checks: List[SecurityCheck], throttle_ms: int = 100):
        self.checks = checks
        self.throttle_ms = throttle_ms
        logger.info(f"Initialized SecurityCheckEngine with {len(checks)} checks")
    
    def execute_checks(self, endpoints: List[Endpoint], config: ScanConfiguration) -> List[CheckResult]:
        """Execute all security checks against all endpoints"""
        results = []
        total_checks = len(endpoints) * len(self.checks)
        completed = 0
        
        logger.info(f"Starting security checks: {len(endpoints)} endpoints × {len(self.checks)} checks = {total_checks} total")
        
        for endpoint in endpoints:
            # Skip excluded endpoints
            if endpoint.path in config.excluded_endpoints:
                logger.info(f"Skipping excluded endpoint: {endpoint.path}")
                continue
            
            logger.info(f"Scanning endpoint: {endpoint.path}")
            
            for check in self.checks:
                # Skip checks not in the configured list (if specified)
                if config.security_checks and check.check_name() not in config.security_checks:
                    logger.debug(f"Skipping check {check.check_name()} (not in configuration)")
                    continue
                
                try:
                    logger.debug(f"Executing {check.check_name()} on {endpoint.path}")
                    result = check.execute(endpoint, config)
                    results.append(result)
                    
                    if result.vulnerable:
                        logger.warning(f"Vulnerability found: {result.evidence}")
                    
                    completed += 1
                    
                    # Progress logging
                    if completed % 10 == 0:
                        progress = (completed / total_checks) * 100
                        logger.info(f"Progress: {completed}/{total_checks} ({progress:.1f}%)")
                    
                    # Throttle requests
                    if self.throttle_ms > 0 and not config.dry_run:
                        time.sleep(self.throttle_ms / 1000.0)
                
                except Exception as e:
                    logger.error(f"Error executing {check.check_name()} on {endpoint.path}: {e}")
                    # Continue with remaining checks
                    results.append(CheckResult(
                        check_name=check.check_name(),
                        endpoint=endpoint.path,
                        vulnerable=False,
                        evidence=f"Check failed with error: {str(e)}"
                    ))
        
        logger.info(f"Completed {completed} security checks")
        return results
    
    def execute_dry_run(self, endpoints: List[Endpoint], config: ScanConfiguration) -> List[str]:
        """Simulate checks without sending requests"""
        planned_checks = []
        
        for endpoint in endpoints:
            if endpoint.path in config.excluded_endpoints:
                continue
            
            for check in self.checks:
                if config.security_checks and check.check_name() not in config.security_checks:
                    continue
                
                planned_checks.append(f"{check.check_name()} on {endpoint.path}")
        
        logger.info(f"Dry run: would execute {len(planned_checks)} checks")
        return planned_checks
