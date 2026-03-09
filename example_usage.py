#!/usr/bin/env python3
"""
Example usage of the API Vulnerability Scanner.
"""

import logging
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def example_basic_scan():
    """Example: Basic scan with minimal configuration"""
    print("\n" + "=" * 80)
    print("Example 1: Basic Scan")
    print("=" * 80)
    
    # Create configuration
    config = ScanConfiguration(
        base_url='https://jsonplaceholder.typicode.com',
        endpoints=['/posts', '/users', '/comments'],
        dry_run=False,  # Set to True to simulate without actual requests
        verbose_logging=True
    )
    
    # Initialize scanner
    scanner = VulnerabilityScanner(config)
    
    # Run scan
    report = scanner.scan()
    
    # Export reports
    scanner.export_report(report, 'basic_scan_report.json', 'json')
    scanner.export_report(report, 'basic_scan_report.html', 'html')
    
    print(f"\nScan completed!")
    print(f"Endpoints scanned: {report.endpoints_scanned}")
    print(f"Vulnerabilities found: {len(report.alerts)}")


def example_advanced_scan():
    """Example: Advanced scan with custom configuration"""
    print("\n" + "=" * 80)
    print("Example 2: Advanced Scan with Custom Configuration")
    print("=" * 80)
    
    # Create advanced configuration
    config = ScanConfiguration(
        base_url='https://api.example.com',
        endpoints=['/api/v1/users', '/api/v1/products', '/api/v1/orders'],
        excluded_endpoints=['/api/v1/health'],
        security_checks=[
            'authentication_check',
            'injection_check',
            'sensitive_data_check'
        ],
        custom_headers={
            'User-Agent': 'API-Security-Scanner/1.0',
            'X-API-Key': 'your-api-key-here'
        },
        severity_threshold=SeverityLevel.MEDIUM,
        dry_run=True,  # Simulate scan
        request_throttle_ms=200,
        verbose_logging=True
    )
    
    # Initialize scanner
    scanner = VulnerabilityScanner(config)
    
    # Load false positives
    # scanner.load_false_positives('false_positives.json')
    
    # Run scan
    report = scanner.scan()
    
    # Export report
    scanner.export_report(report, 'advanced_scan_report.json', 'json')
    
    print(f"\nScan completed!")
    print(f"Vulnerabilities found: {len(report.alerts)}")


def example_with_false_positives():
    """Example: Managing false positives"""
    print("\n" + "=" * 80)
    print("Example 3: Managing False Positives")
    print("=" * 80)
    
    config = ScanConfiguration(
        base_url='https://api.example.com',
        endpoints=['/api/users'],
        dry_run=True
    )
    
    scanner = VulnerabilityScanner(config)
    
    # Load existing false positives
    scanner.load_false_positives('false_positives.json')
    
    # Run scan
    report = scanner.scan()
    
    # Mark an alert as false positive (if any)
    if report.alerts:
        first_alert = report.alerts[0]
        scanner.mark_false_positive(first_alert, marked_by='security_team@example.com')
        print(f"Marked alert {first_alert.id} as false positive")
    
    # Save updated false positives
    scanner.save_false_positives('false_positives.json')
    
    print(f"False positives database updated")


def example_config_file():
    """Example: Using configuration file"""
    print("\n" + "=" * 80)
    print("Example 4: Using Configuration File")
    print("=" * 80)
    
    # Create example config file
    import json
    
    config_data = {
        "base_url": "https://api.example.com",
        "endpoints": ["/api/users", "/api/products"],
        "excluded_endpoints": ["/api/health"],
        "security_checks": ["authentication_check", "injection_check"],
        "custom_headers": {
            "User-Agent": "API-Security-Scanner/1.0"
        },
        "severity_threshold": "medium",
        "dry_run": True,
        "read_only": True,
        "request_throttle_ms": 100,
        "verbose_logging": False
    }
    
    with open('scan_config.json', 'w') as f:
        json.dump(config_data, f, indent=2)
    
    print("Created scan_config.json")
    
    # Load and use config
    scanner = VulnerabilityScanner()
    scanner.load_config('scan_config.json')
    
    report = scanner.scan()
    scanner.export_report(report, 'config_scan_report.json', 'json')
    
    print(f"Scan completed using configuration file")


def example_severity_filtering():
    """Example: Filtering by severity"""
    print("\n" + "=" * 80)
    print("Example 5: Severity Filtering")
    print("=" * 80)
    
    # Scan with different severity thresholds
    for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM]:
        config = ScanConfiguration(
            base_url='https://api.example.com',
            endpoints=['/api/users'],
            severity_threshold=severity,
            dry_run=True
        )
        
        scanner = VulnerabilityScanner(config)
        report = scanner.scan()
        
        print(f"\nSeverity threshold: {severity.value.upper()}")
        print(f"Alerts reported: {len(report.alerts)}")


if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("API VULNERABILITY SCANNER - EXAMPLE USAGE")
    print("=" * 80)
    
    # Run examples
    try:
        # Example 1: Basic scan
        example_basic_scan()
        
        # Example 2: Advanced scan
        # example_advanced_scan()
        
        # Example 3: False positives
        # example_with_false_positives()
        
        # Example 4: Config file
        # example_config_file()
        
        # Example 5: Severity filtering
        # example_severity_filtering()
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 80)
    print("Examples completed!")
    print("=" * 80)
