#!/usr/bin/env python3
"""
Command-line interface for the API Vulnerability Scanner.
"""

import argparse
import logging
import sys
from pathlib import Path
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description='API Vulnerability Scanner - Ethical hacking tool for API security testing'
    )
    
    parser.add_argument(
        'base_url',
        help='Base URL of the API to scan (e.g., https://api.example.com)'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file (JSON)'
    )
    
    parser.add_argument(
        '--endpoints',
        nargs='+',
        help='List of endpoints to scan (e.g., /api/users /api/products)'
    )
    
    parser.add_argument(
        '--exclude',
        nargs='+',
        default=[],
        help='List of endpoints to exclude from scanning'
    )
    
    parser.add_argument(
        '--checks',
        nargs='+',
        help='Specific security checks to run (default: all)'
    )
    
    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='info',
        help='Minimum severity level to report (default: info)'
    )
    
    parser.add_argument(
        '--output',
        default='scan_report',
        help='Output file path (without extension)'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'html', 'pdf', 'all'],
        default='json',
        help='Report format (default: json)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate scan without sending actual requests'
    )
    
    parser.add_argument(
        '--throttle',
        type=int,
        default=100,
        help='Request throttle in milliseconds (default: 100)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--false-positives',
        help='Path to false positive database'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner()
        
        # Load false positives if provided
        if args.false_positives:
            scanner.load_false_positives(args.false_positives)
        
        # Load or create configuration
        if args.config:
            scanner.load_config(args.config)
        else:
            config = ScanConfiguration(
                base_url=args.base_url,
                endpoints=args.endpoints,
                excluded_endpoints=args.exclude,
                security_checks=args.checks or [],
                severity_threshold=SeverityLevel(args.severity),
                dry_run=args.dry_run,
                request_throttle_ms=args.throttle,
                verbose_logging=args.verbose
            )
        
        # Run scan
        logger.info(f"Starting scan of {args.base_url}")
        report = scanner.scan(config if not args.config else None)
        
        # Export reports
        formats = ['json', 'html', 'pdf'] if args.format == 'all' else [args.format]
        
        for fmt in formats:
            output_file = f"{args.output}.{fmt}"
            scanner.export_report(report, output_file, fmt)
            print(f"Report exported to: {output_file}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("SCAN SUMMARY")
        print("=" * 80)
        print(f"Scan ID: {report.scan_id}")
        print(f"Target: {report.configuration.base_url}")
        print(f"Endpoints Scanned: {report.endpoints_scanned}")
        print(f"Checks Performed: {report.checks_performed}")
        print(f"Vulnerabilities Found: {len(report.alerts)}")
        print(f"Scan Duration: {report.scan_duration.total_seconds():.1f} seconds")
        
        if report.alerts:
            print("\nVULNERABILITIES:")
            severity_counts = {}
            for alert in report.alerts:
                severity = alert.vulnerability.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_counts:
                    print(f"  {severity.upper()}: {severity_counts[severity]}")
        else:
            print("\nNo vulnerabilities detected!")
        
        print("=" * 80)
        
        # Exit with appropriate code
        if any(alert.vulnerability.severity.value in ['critical', 'high'] for alert in report.alerts):
            sys.exit(1)
        else:
            sys.exit(0)
    
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(2)


if __name__ == '__main__':
    main()
