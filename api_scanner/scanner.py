"""
Main Vulnerability Scanner class.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from .models import (
    ScanConfiguration,
    Endpoint,
    ScanReport,
    Alert,
)
from .config_manager import ConfigurationManager
from .endpoint_discovery import EndpointDiscovery
from .security_check_engine import SecurityCheckEngine
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .alert_generator import AlertGenerator
from .report_exporter import ReportExporter
from .progress_monitor import ProgressMonitor
from .false_positive_db import FalsePositiveDatabase
from .security_checks import (
    AuthenticationCheck,
    InjectionCheck,
    AccessControlCheck,
    SensitiveDataCheck,
    RateLimitCheck,
    SecurityMisconfigurationCheck,
)

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """Main API Vulnerability Scanner"""
    
    def __init__(self, config: Optional[ScanConfiguration] = None):
        self.config = config
        self.config_manager = ConfigurationManager()
        self.false_positive_db = FalsePositiveDatabase()
        self.progress_monitor = ProgressMonitor()
        
        # Initialize components
        self.vulnerability_analyzer = VulnerabilityAnalyzer(self.false_positive_db)
        self.alert_generator = AlertGenerator()
        self.report_exporter = ReportExporter()
        
        logger.info("Initialized VulnerabilityScanner")
    
    def load_config(self, config_path: str) -> None:
        """Load configuration from file"""
        self.config = self.config_manager.load_config(config_path)
        logger.info(f"Loaded configuration from {config_path}")
    
    def load_false_positives(self, db_path: str) -> None:
        """Load false positive database"""
        self.false_positive_db.load(db_path)
    
    def save_false_positives(self, db_path: str) -> None:
        """Save false positive database"""
        self.false_positive_db.save(db_path)
    
    def scan(self, config: Optional[ScanConfiguration] = None) -> ScanReport:
        """Execute a complete vulnerability scan"""
        if config:
            self.config = config
        
        if not self.config:
            raise ValueError("No configuration provided. Call load_config() or provide config parameter.")
        
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"Starting scan {scan_id} for {self.config.base_url}")
        
        # Phase 1: Discovery
        logger.info("Phase 1: Endpoint Discovery")
        endpoints = self._discover_endpoints()
        logger.info(f"Discovered {len(endpoints)} endpoints")
        
        # Phase 2: Security Checks
        logger.info("Phase 2: Security Checks")
        check_results = self._execute_security_checks(endpoints)
        logger.info(f"Completed {len(check_results)} security checks")
        
        # Phase 3: Analysis
        logger.info("Phase 3: Vulnerability Analysis")
        vulnerabilities = self.vulnerability_analyzer.analyze(check_results)
        logger.info(f"Identified {len(vulnerabilities)} vulnerabilities")
        
        # Phase 4: Alert Generation
        logger.info("Phase 4: Alert Generation")
        alerts = self._generate_alerts(vulnerabilities)
        logger.info(f"Generated {len(alerts)} alerts")
        
        # Apply severity threshold filtering
        alerts = self._filter_by_severity(alerts)
        logger.info(f"After severity filtering: {len(alerts)} alerts")
        
        # Create scan report
        end_time = datetime.now()
        scan_duration = end_time - start_time
        
        report = ScanReport(
            scan_id=scan_id,
            timestamp=start_time,
            configuration=self.config,
            endpoints_scanned=len(endpoints),
            checks_performed=len(check_results),
            alerts=alerts,
            scan_duration=scan_duration
        )
        
        logger.info(f"Scan {scan_id} completed in {scan_duration.total_seconds():.1f} seconds")
        return report
    
    def _discover_endpoints(self) -> List[Endpoint]:
        """Discover API endpoints"""
        discovery = EndpointDiscovery(self.config.base_url)
        endpoints = []
        
        # Try OpenAPI discovery first
        if hasattr(self.config, 'openapi_spec_url') and self.config.openapi_spec_url:
            logger.info("Attempting OpenAPI discovery")
            endpoints = discovery.discover_from_openapi(self.config.openapi_spec_url)
        
        # Fall back to manual configuration
        if not endpoints and self.config.endpoints:
            logger.info("Using manual endpoint configuration")
            endpoints = discovery.discover_from_manual(self.config.endpoints)
        
        # If still no endpoints, try common paths
        if not endpoints:
            logger.warning("No endpoints discovered, using default paths")
            default_paths = ['/api', '/api/v1', '/']
            endpoints = discovery.discover_from_manual(default_paths)
        
        return endpoints
    
    def _execute_security_checks(self, endpoints: List[Endpoint]) -> List:
        """Execute all security checks"""
        # Initialize security checks
        checks = [
            AuthenticationCheck(),
            InjectionCheck(),
            AccessControlCheck(),
            SensitiveDataCheck(),
            RateLimitCheck(),
            SecurityMisconfigurationCheck(),
        ]
        
        # Create security check engine
        engine = SecurityCheckEngine(checks, self.config.request_throttle_ms)
        
        # Execute checks
        if self.config.dry_run:
            logger.info("Dry run mode - simulating checks")
            planned_checks = engine.execute_dry_run(endpoints, self.config)
            logger.info(f"Would execute {len(planned_checks)} checks")
            return []
        else:
            # Start progress monitoring
            total_checks = len(endpoints) * len(checks)
            self.progress_monitor.start_scan(total_checks)
            
            results = engine.execute_checks(endpoints, self.config)
            return results
    
    def _generate_alerts(self, vulnerabilities: List) -> List[Alert]:
        """Generate alerts for vulnerabilities"""
        alerts = []
        
        for vulnerability in vulnerabilities:
            alert = self.alert_generator.generate_alert(vulnerability)
            alerts.append(alert)
        
        return alerts
    
    def _filter_by_severity(self, alerts: List[Alert]) -> List[Alert]:
        """Filter alerts by severity threshold"""
        severity_order = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1,
        }
        
        threshold_level = severity_order[self.config.severity_threshold.value]
        
        filtered = [
            alert for alert in alerts
            if severity_order[alert.vulnerability.severity.value] >= threshold_level
        ]
        
        return filtered
    
    def export_report(self, report: ScanReport, output_path: str, format: str = 'json') -> None:
        """Export scan report to file"""
        if format == 'json':
            self.report_exporter.export_json(report, output_path)
        elif format == 'html':
            self.report_exporter.export_html(report, output_path)
        elif format == 'pdf':
            self.report_exporter.export_pdf(report, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Exported report to {output_path} ({format})")
    
    def mark_false_positive(self, alert: Alert, marked_by: str) -> None:
        """Mark an alert as false positive"""
        self.false_positive_db.mark_false_positive(alert, marked_by)
        logger.info(f"Marked alert {alert.id} as false positive")
