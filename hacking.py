#!/usr/bin/env python3
"""
API Vulnerability Scanner - Quick Start
Ethical hacking tool for checking API vulnerabilities and alerting users.
"""

import sys
import os

# Add parent directory to path to import api_scanner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def scan_api(target_url, endpoints=None):
    """
    Scan an API for vulnerabilities and generate alerts.
    
    Args:
        target_url: Base URL of the API to scan
        endpoints: List of endpoints to scan (optional)
    """
    print("\n" + "=" * 80)
    print("API VULNERABILITY SCANNER")
    print("Ethical Hacking Tool for API Security Testing")
    print("=" * 80)
    
    # Default endpoints if none provided
    if not endpoints:
        endpoints = ['/api', '/api/v1', '/']
    
    # Create scan configuration
    config = ScanConfiguration(
        base_url=target_url,
        endpoints=endpoints,
        severity_threshold=SeverityLevel.INFO,
        dry_run=False,  # Set to True to simulate without actual requests
        request_throttle_ms=100,  # Be respectful to the target
        verbose_logging=True
    )
    
    print(f"\nTarget: {target_url}")
    print(f"Endpoints: {', '.join(endpoints)}")
    print("\nStarting security scan...\n")
    
    # Initialize scanner
    scanner = VulnerabilityScanner(config)
    
    # Run the scan
    report = scanner.scan()
    
    # Generate alerts and reports
    print("\n" + "=" * 80)
    print("SCAN RESULTS - SECURITY ALERTS")
    print("=" * 80)
    
    if report.alerts:
        print(f"\n⚠️  FOUND {len(report.alerts)} VULNERABILITIES!\n")
        
        # Group by severity
        critical = [a for a in report.alerts if a.vulnerability.severity.value == 'critical']
        high = [a for a in report.alerts if a.vulnerability.severity.value == 'high']
        medium = [a for a in report.alerts if a.vulnerability.severity.value == 'medium']
        low = [a for a in report.alerts if a.vulnerability.severity.value == 'low']
        
        if critical:
            print(f"🔴 CRITICAL: {len(critical)}")
        if high:
            print(f"🟠 HIGH: {len(high)}")
        if medium:
            print(f"🟡 MEDIUM: {len(medium)}")
        if low:
            print(f"🔵 LOW: {len(low)}")
        
        print("\n" + "-" * 80)
        print("DETAILED ALERTS:")
        print("-" * 80)
        
        for i, alert in enumerate(report.alerts, 1):
            vuln = alert.vulnerability
            print(f"\n{i}. {vuln.type.replace('_', ' ').upper()}")
            print(f"   Severity: {vuln.severity.value.upper()}")
            print(f"   Confidence: {vuln.confidence:.0%}")
            print(f"   Endpoint: {vuln.endpoint}")
            print(f"   Evidence: {vuln.evidence}")
            print(f"   OWASP: {alert.remediation.owasp_mapping}")
            
            print(f"\n   📋 Remediation Steps:")
            for j, step in enumerate(alert.remediation.steps[:3], 1):
                print(f"      {j}. {step}")
            
            if alert.requires_manual_verification:
                print(f"   ⚠️  Requires manual verification")
    else:
        print("\n✅ No vulnerabilities detected!")
        print("The API appears to be secure based on the checks performed.")
    
    # Export reports
    print("\n" + "=" * 80)
    print("EXPORTING REPORTS")
    print("=" * 80)
    
    scanner.export_report(report, 'vulnerability_report_1.json', 'json')
    print("✓ JSON report: vulnerability_report.json")
    
    scanner.export_report(report, 'vulnerability_report_1.html', 'html')
    print("✓ HTML report: vulnerability_report.html")
    
    # Summary
    print("\n" + "=" * 80)
    print("SCAN SUMMARY")
    print("=" * 80)
    print(f"Scan ID: {report.scan_id}")
    print(f"Endpoints Scanned: {report.endpoints_scanned}")
    print(f"Security Checks: {report.checks_performed}")
    print(f"Vulnerabilities: {len(report.alerts)}")
    print(f"Duration: {report.scan_duration.total_seconds():.1f} seconds")
    print("=" * 80 + "\n")
    
    return report


if __name__ == '__main__':
    # Example usage
    print("\nAPI Vulnerability Scanner - Ethical Hacking Tool")
    print("=" * 80)
    
    # Scan CampusNotes Authentication API for vulnerabilities
    print("\nScanning CampusNotes Authentication API for vulnerabilities...")
    print("-" * 80)
    
    report = scan_api(
        target_url='https://huggingface.co/spaces/aravindh007/campusnotes-authentication',
        endpoints=[
            '/',
            '/api',
            '/auth',
            '/login', 
            '/register',
            '/signup',
            '/authenticate',
            '/verify',
            '/token',
            '/users',
            '/session',
            '/logout'
        ]
    )
    
    print("\n✅ Scan completed! Check the generated reports for details.")
    print("\nReports generated:")
    print("  - vulnerability_report.json (machine-readable)")
    print("  - vulnerability_report.html (open in browser)")
    print("\nIMPORTANT: This scan was performed for security testing purposes.")
    print("Review the reports to see all detected vulnerabilities.\n")
