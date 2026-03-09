#!/usr/bin/env python3
"""
Simple test to verify the API Vulnerability Scanner works.
"""

import logging
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def test_dry_run():
    """Test scanner in dry-run mode"""
    print("\n" + "=" * 80)
    print("Testing API Vulnerability Scanner (Dry Run)")
    print("=" * 80)
    
    # Create configuration for a public test API
    config = ScanConfiguration(
        base_url='https://jsonplaceholder.typicode.com',
        endpoints=['/posts', '/users', '/comments'],
        dry_run=True,  # Dry run - no actual requests
        verbose_logging=True,
        request_throttle_ms=100
    )
    
    # Initialize scanner
    print("\n1. Initializing scanner...")
    scanner = VulnerabilityScanner(config)
    print("   ✓ Scanner initialized")
    
    # Run scan
    print("\n2. Running scan (dry run mode)...")
    report = scanner.scan()
    print(f"   ✓ Scan completed")
    
    # Verify report
    print("\n3. Verifying report...")
    assert report.scan_id is not None, "Scan ID should be generated"
    assert report.configuration.base_url == config.base_url, "Base URL should match"
    print(f"   ✓ Report generated with ID: {report.scan_id}")
    
    # Export reports
    print("\n4. Exporting reports...")
    scanner.export_report(report, 'test_report.json', 'json')
    print("   ✓ JSON report exported to test_report.json")
    
    scanner.export_report(report, 'test_report.html', 'html')
    print("   ✓ HTML report exported to test_report.html")
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST RESULTS")
    print("=" * 80)
    print(f"Scan ID: {report.scan_id}")
    print(f"Target: {report.configuration.base_url}")
    print(f"Endpoints: {len(config.endpoints)}")
    print(f"Duration: {report.scan_duration.total_seconds():.2f} seconds")
    print(f"Status: ✓ All tests passed!")
    print("=" * 80)
    
    return True


def test_live_scan():
    """Test scanner with actual requests (safe public API)"""
    print("\n" + "=" * 80)
    print("Testing API Vulnerability Scanner (Live Scan)")
    print("=" * 80)
    print("\nNote: This will make actual requests to a public test API")
    
    # Create configuration for a public test API
    config = ScanConfiguration(
        base_url='https://jsonplaceholder.typicode.com',
        endpoints=['/posts/1'],  # Single endpoint for quick test
        dry_run=False,  # Live scan
        verbose_logging=False,
        request_throttle_ms=200,  # Be respectful
        severity_threshold=SeverityLevel.INFO
    )
    
    # Initialize scanner
    print("\n1. Initializing scanner...")
    scanner = VulnerabilityScanner(config)
    print("   ✓ Scanner initialized")
    
    # Run scan
    print("\n2. Running live scan...")
    print("   (This may take a moment...)")
    report = scanner.scan()
    print(f"   ✓ Scan completed")
    
    # Export report
    print("\n3. Exporting report...")
    scanner.export_report(report, 'live_scan_report.json', 'json')
    scanner.export_report(report, 'live_scan_report.html', 'html')
    print("   ✓ Reports exported")
    
    # Print summary
    print("\n" + "=" * 80)
    print("LIVE SCAN RESULTS")
    print("=" * 80)
    print(f"Scan ID: {report.scan_id}")
    print(f"Target: {report.configuration.base_url}")
    print(f"Endpoints Scanned: {report.endpoints_scanned}")
    print(f"Checks Performed: {report.checks_performed}")
    print(f"Vulnerabilities Found: {len(report.alerts)}")
    print(f"Duration: {report.scan_duration.total_seconds():.2f} seconds")
    
    if report.alerts:
        print("\nVulnerabilities detected:")
        for alert in report.alerts[:5]:  # Show first 5
            print(f"  - {alert.vulnerability.type} ({alert.vulnerability.severity.value})")
            print(f"    Endpoint: {alert.vulnerability.endpoint}")
            print(f"    Evidence: {alert.vulnerability.evidence[:100]}...")
    else:
        print("\nNo vulnerabilities detected")
    
    print("\n" + "=" * 80)
    print("Status: ✓ Live scan completed successfully!")
    print("=" * 80)
    
    return True


if __name__ == '__main__':
    try:
        # Run dry run test
        print("\n" + "=" * 80)
        print("API VULNERABILITY SCANNER - TEST SUITE")
        print("=" * 80)
        
        test_dry_run()
        
        # Ask user if they want to run live scan
        print("\n" + "=" * 80)
        response = input("\nRun live scan test? (y/n): ").strip().lower()
        if response == 'y':
            test_live_scan()
        else:
            print("Skipping live scan test")
        
        print("\n" + "=" * 80)
        print("✓ ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\nThe API Vulnerability Scanner is ready to use!")
        print("Try running: python example_usage.py")
        print("Or: python cli.py --help")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
