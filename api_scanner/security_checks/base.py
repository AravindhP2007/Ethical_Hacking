"""
Base class for security checks.
"""

from abc import ABC, abstractmethod
from ..models import Endpoint, ScanConfiguration, CheckResult


class SecurityCheck(ABC):
    """Base class for all security checks"""
    
    @abstractmethod
    def check_name(self) -> str:
        """Return the name of this security check"""
        pass
    
    @abstractmethod
    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        """Execute the security check against an endpoint"""
        pass
