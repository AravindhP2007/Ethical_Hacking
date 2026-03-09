"""
Rate limiting detection.
"""

import logging
import time
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)


class RateLimitCheck(SecurityCheck):
    """Tests for rate limiting"""
    
    def check_name(self) -> str:
        return "rate_limit_check"
    
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute rate limiting checks"""
        url = urljoin(config.base_url, endpoint.path)
        
        # Test for rate limiting
        rate_limit_result = self._test_rate_limiting(url, config)
        
        if rate_limit_result:
            return CheckResult(
                check_name=self.check_name(),
                endpoint=endpoint.path,
                vulnerable=True,
                evidence=rate_limit_result
            )
        
        return CheckResult(
            check_name=self.check_name(),
            endpoint=endpoint.path,
            vulnerable=False,
            evidence="Rate limiting is properly configured"
        )
    
    def _test_rate_limiting(self, url: str, config: ScanConfiguration) -> str:
        """Test for absence of rate limiting"""
        if config.dry_run:
            return ""
        
        try:
            # Send multiple rapid requests
            num_requests = 20
            responses = []
            
            logger.info(f"Testing rate limiting with {num_requests} requests to {url}")
            
            for i in range(num_requests):
                try:
                    response = requests.get(url, headers=config.custom_headers, timeout=5)
                    responses.append(response)
                    
                    # Check for rate limit headers
                    rate_limit_headers = [
                        'X-RateLimit-Limit',
                        'X-RateLimit-Remaining',
                        'X-Rate-Limit-Limit',
                        'RateLimit-Limit',
                        'Retry-After'
                    ]
                    
                    has_rate_limit_headers = any(header in response.headers for header in rate_limit_headers)
                    
                    # If we get 429 Too Many Requests, rate limiting is working
                    if response.status_code == 429:
                        logger.info(f"Rate limiting detected at {url}")
                        return ""  # Not vulnerable
                    
                    # Small delay to avoid overwhelming the server
                    time.sleep(0.1)
                
                except requests.RequestException as e:
                    logger.debug(f"Request {i+1} failed: {e}")
            
            # If all requests succeeded without rate limiting
            successful_requests = sum(1 for r in responses if r.status_code == 200)
            
            if successful_requests >= num_requests * 0.9:  # 90% success rate
                # Check if any response had rate limit headers
                has_any_rate_limit_headers = any(
                    any(header in r.headers for header in ['X-RateLimit-Limit', 'X-Rate-Limit-Limit', 'RateLimit-Limit'])
                    for r in responses
                )
                
                if not has_any_rate_limit_headers:
                    logger.warning(f"No rate limiting detected at {url}")
                    return f"No rate limiting detected - {successful_requests}/{num_requests} requests succeeded"
        
        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")
        
        return ""
