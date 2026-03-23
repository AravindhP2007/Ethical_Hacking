"""
Progress Monitor for tracking scan progress.
"""

import logging
import time
from datetime import datetime
from .models import ScanProgress

logger = logging.getLogger(__name__)


class ProgressMonitor:
    """Tracks and reports scan progress"""
    
    def __init__(self):
        self.total_checks = 0
        self.completed_checks = 0
        self.current_endpoint = ""
        self.current_check = ""
        self.start_time = None
        self.check_times = []
    
    def start_scan(self, total_checks: int) -> None:
        """Initialize progress tracking for a new scan"""
        self.total_checks = total_checks
        self.completed_checks = 0
        self.start_time = time.time()
        self.check_times = []
        logger.info(f"Started progress monitoring for {total_checks} checks")
    
    def update_progress(self, completed: int, total: int, endpoint: str = "", check: str = "") -> None:
        """Update progress tracking"""
        self.completed_checks = completed
        self.total_checks = total
        self.current_endpoint = endpoint
        self.current_check = check
        
        # Record check time for estimation
        if self.start_time:
            elapsed = time.time() - self.start_time
            if completed > 0:
                avg_time_per_check = elapsed / completed
                self.check_times.append(avg_time_per_check)
    
    def get_progress(self) -> ScanProgress:
        """Get current progress state"""
        estimated_remaining = self.estimate_remaining_time()
        
        return ScanProgress(
            total_checks=self.total_checks,
            completed_checks=self.completed_checks,
            current_endpoint=self.current_endpoint,
            current_check=self.current_check,
            estimated_remaining_seconds=estimated_remaining
        )
    
    def log_check(self, check_name: str, endpoint: str, result: str) -> None:
        """Log security check execution"""
        timestamp = datetime.now().isoformat()
        logger.info(f"[{timestamp}] {check_name} on {endpoint}: {result}")
    
    def estimate_remaining_time(self) -> int:
        """Estimate seconds remaining in scan"""
        if self.completed_checks == 0 or not self.start_time:
            return 0
        
        elapsed = time.time() - self.start_time
        avg_time_per_check = elapsed / self.completed_checks
        remaining_checks = self.total_checks - self.completed_checks
        
        return int(remaining_checks * avg_time_per_check)
    
    def get_progress_percentage(self) -> float:
        """Get progress as percentage"""
        if self.total_checks == 0:
            return 0.0
        return (self.completed_checks / self.total_checks) * 100
    
    def print_progress(self) -> None:
        """Print progress to console"""
        percentage = self.get_progress_percentage()
        remaining = self.estimate_remaining_time()
        
        print(f"\rProgress: {self.completed_checks}/{self.total_checks} ({percentage:.1f}%) - "
              f"Est. remaining: {remaining}s", end='', flush=True)
