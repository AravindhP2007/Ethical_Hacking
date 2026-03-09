# API Vulnerability Scanner - Project Summary

## Overview

A comprehensive ethical hacking tool for detecting security vulnerabilities in REST APIs. The scanner performs automated security checks, detects potential weaknesses, and provides actionable alerts with remediation guidance.

## Project Structure

```
api-vulnerability-scanner/
├── api_scanner/                    # Main package
│   ├── __init__.py                # Package initialization
│   ├── models.py                  # Data models and enums
│   ├── config_manager.py          # Configuration management
│   ├── endpoint_discovery.py      # API endpoint discovery
│   ├── security_check_engine.py   # Security check orchestration
│   ├── vulnerability_analyzer.py  # Vulnerability analysis
│   ├── alert_generator.py         # Alert generation with remediation
│   ├── report_exporter.py         # Report export (JSON/HTML/PDF)
│   ├── progress_monitor.py        # Scan progress tracking
│   ├── false_positive_db.py       # False positive management
│   ├── scanner.py                 # Main scanner class
│   └── security_checks/           # Security check implementations
│       ├── __init__.py
│       ├── base.py                # Base security check class
│       ├── authentication_check.py
│       ├── injection_check.py
│       ├── access_control_check.py
│       ├── sensitive_data_check.py
│       ├── rate_limit_check.py
│       └── security_misconfiguration_check.py
├── cli.py                         # Command-line interface
├── example_usage.py               # Usage examples
├── test_scanner.py                # Test suite
├── .vscode/hacking.py            # Quick start script
├── README.md                      # Full documentation
├── QUICKSTART.md                  # Quick start guide
├── requirements.txt               # Python dependencies
└── .gitignore                     # Git ignore rules
```

## Key Features

### 1. Comprehensive Security Checks
- **Authentication**: Missing auth, weak schemes, default credentials
- **Injection**: SQL, NoSQL, Command, XML injection
- **Access Control**: IDOR, privilege escalation, broken authorization
- **Sensitive Data**: Exposed credentials, missing HTTPS, data leakage
- **Rate Limiting**: Absence or misconfiguration
- **Security Misconfiguration**: Verbose errors, missing headers

### 2. Smart Analysis
- Automatic severity assignment (Critical/High/Medium/Low/Info)
- Confidence scoring (0-100%)
- False positive management with persistent database
- OWASP API Security Top 10 mapping

### 3. Flexible Configuration
- JSON configuration files
- Command-line interface with rich options
- Programmatic Python API
- Custom security check selection
- Endpoint inclusion/exclusion

### 4. Multiple Report Formats
- **JSON**: Machine-readable for automation
- **HTML**: Styled, human-readable reports
- **PDF**: Portable document format (text-based)

### 5. Safe Operation
- Read-only mode by default
- Dry-run simulation mode
- Request throttling to avoid overwhelming targets
- Error resilience - continues on failures
- Comprehensive logging

## Components

### Core Components

1. **ConfigurationManager**: Loads and validates scan configurations
2. **EndpointDiscovery**: Discovers endpoints from OpenAPI specs or manual config
3. **SecurityCheckEngine**: Orchestrates security check execution
4. **VulnerabilityAnalyzer**: Analyzes results and identifies vulnerabilities
5. **AlertGenerator**: Creates alerts with remediation guidance
6. **ReportExporter**: Exports reports in multiple formats
7. **ProgressMonitor**: Tracks and reports scan progress
8. **FalsePositiveDatabase**: Manages false positive entries
9. **VulnerabilityScanner**: Main scanner class that ties everything together

### Security Checks

1. **AuthenticationCheck**: Tests authentication vulnerabilities
2. **InjectionCheck**: Tests for injection attacks
3. **AccessControlCheck**: Tests access control issues
4. **SensitiveDataCheck**: Tests for data exposure
5. **RateLimitCheck**: Tests rate limiting
6. **SecurityMisconfigurationCheck**: Tests security misconfigurations

## Usage Examples

### Command Line

```bash
# Basic scan
python cli.py https://api.example.com --endpoints /api/users

# Full scan with all options
python cli.py https://api.example.com \
  --endpoints /api/users /api/products \
  --exclude /api/health \
  --severity high \
  --format all \
  --throttle 200 \
  --output scan_report

# Dry run
python cli.py https://api.example.com --endpoints /api/users --dry-run
```

### Python API

```python
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel

# Configure
config = ScanConfiguration(
    base_url='https://api.example.com',
    endpoints=['/api/users', '/api/products'],
    severity_threshold=SeverityLevel.MEDIUM,
    dry_run=False
)

# Scan
scanner = VulnerabilityScanner(config)
report = scanner.scan()

# Export
scanner.export_report(report, 'report.json', 'json')
scanner.export_report(report, 'report.html', 'html')

# Results
print(f"Found {len(report.alerts)} vulnerabilities")
for alert in report.alerts:
    print(f"- {alert.vulnerability.type}: {alert.vulnerability.severity.value}")
```

### Quick Start Script

```bash
python .vscode/hacking.py
```

## Technical Details

### Data Models

- **ScanConfiguration**: Scan parameters and settings
- **Endpoint**: API endpoint representation
- **CheckResult**: Result from a security check
- **Vulnerability**: Detected vulnerability with metadata
- **Alert**: Security alert with remediation guidance
- **ScanReport**: Complete scan report with all findings

### Severity Levels

- **CRITICAL**: Injection attacks, critical security flaws
- **HIGH**: Authentication bypass, broken access control, data exposure
- **MEDIUM**: Missing rate limits, security misconfigurations
- **LOW**: Minor issues
- **INFO**: Informational findings

### OWASP API Security Top 10 Coverage

- API1:2023 Broken Object Level Authorization
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization
- API4:2023 Unrestricted Resource Consumption
- API5:2023 Broken Function Level Authorization
- API8:2023 Security Misconfiguration

## Testing

Run the test suite:

```bash
python test_scanner.py
```

Tests include:
- Dry-run mode verification
- Live scan against public test API
- Report generation
- Component integration

## Dependencies

- **requests**: HTTP client for API testing
- **urllib3**: URL handling
- **pytest** (optional): Testing framework
- **hypothesis** (optional): Property-based testing

## Best Practices

1. **Always get authorization** before scanning
2. **Start with dry-run** to understand what will be tested
3. **Use read-only mode** for production systems
4. **Enable throttling** to be respectful
5. **Review false positives** regularly
6. **Test in staging** first
7. **Monitor logs** for issues
8. **Keep updated** with latest security checks

## Ethical Usage

✅ **DO**:
- Get explicit permission before testing
- Use for authorized security assessments
- Follow responsible disclosure
- Respect rate limits and resources

❌ **DON'T**:
- Use for unauthorized access
- Use to harm or disrupt services
- Use for illegal activities
- Test production without permission

## Future Enhancements

Potential improvements:
- Additional security checks (CORS, CSRF, etc.)
- OpenAPI 3.0 full support
- GraphQL API support
- WebSocket testing
- Authentication token handling
- Parallel scanning
- Machine learning for false positive detection
- Integration with CI/CD pipelines
- Web UI dashboard
- Real-time monitoring mode

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: README.md and QUICKSTART.md
- Examples: example_usage.py

---

**Built with security in mind. Use responsibly.** 🔒
