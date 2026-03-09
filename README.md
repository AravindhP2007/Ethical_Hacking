# API Vulnerability Scanner

An ethical hacking tool for detecting security vulnerabilities in REST APIs. This scanner performs automated security checks, detects potential weaknesses, and provides actionable alerts with remediation guidance to help developers secure their APIs.

## Features

- **Comprehensive Security Checks**
  - Authentication vulnerability detection
  - Injection attack detection (SQL, NoSQL, Command, XML)
  - Broken access control detection
  - Sensitive data exposure detection
  - Rate limiting verification
  - Security misconfiguration detection

- **Smart Analysis**
  - Automatic severity assignment
  - Confidence scoring
  - False positive management
  - OWASP API Security Top 10 mapping

- **Flexible Configuration**
  - JSON configuration files
  - Command-line interface
  - Programmatic API
  - Custom security check selection

- **Multiple Report Formats**
  - JSON (machine-readable)
  - HTML (human-readable with styling)
  - PDF (portable document)

- **Safe Operation**
  - Read-only mode by default
  - Dry-run simulation
  - Request throttling
  - Error resilience

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/api-vulnerability-scanner.git
cd api-vulnerability-scanner

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Command Line Usage

```bash
# Basic scan
python cli.py https://api.example.com --endpoints /api/users /api/products

# Scan with custom configuration
python cli.py https://api.example.com --config scan_config.json

# Dry run (simulate without actual requests)
python cli.py https://api.example.com --endpoints /api/users --dry-run

# Export to multiple formats
python cli.py https://api.example.com --endpoints /api/users --format all

# Filter by severity
python cli.py https://api.example.com --endpoints /api/users --severity high
```

### Programmatic Usage

```python
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel

# Create configuration
config = ScanConfiguration(
    base_url='https://api.example.com',
    endpoints=['/api/users', '/api/products'],
    severity_threshold=SeverityLevel.MEDIUM,
    dry_run=False
)

# Initialize scanner
scanner = VulnerabilityScanner(config)

# Run scan
report = scanner.scan()

# Export report
scanner.export_report(report, 'scan_report.json', 'json')
scanner.export_report(report, 'scan_report.html', 'html')

# Print summary
print(f"Vulnerabilities found: {len(report.alerts)}")
for alert in report.alerts:
    print(f"- {alert.vulnerability.type}: {alert.vulnerability.evidence}")
```

## Configuration File Format

Create a `scan_config.json` file:

```json
{
  "base_url": "https://api.example.com",
  "endpoints": ["/api/users", "/api/products"],
  "excluded_endpoints": ["/api/health"],
  "security_checks": [
    "authentication_check",
    "injection_check",
    "access_control_check",
    "sensitive_data_check",
    "rate_limit_check",
    "security_misconfiguration_check"
  ],
  "custom_headers": {
    "User-Agent": "API-Security-Scanner/1.0",
    "X-API-Key": "your-api-key-here"
  },
  "severity_threshold": "medium",
  "dry_run": false,
  "read_only": true,
  "request_throttle_ms": 100,
  "verbose_logging": false
}
```

## Security Checks

### 1. Authentication Check
- Missing authentication on protected endpoints
- Weak authentication schemes
- Default credentials
- Token expiration issues

### 2. Injection Check
- SQL injection
- NoSQL injection
- Command injection
- XML injection (XXE)

### 3. Access Control Check
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Privilege escalation

### 4. Sensitive Data Check
- Unencrypted sensitive data in responses
- HTTPS enforcement
- Sensitive data in error messages
- Exposed API keys and tokens

### 5. Rate Limiting Check
- Absence of rate limiting
- Improper rate limit configuration

### 6. Security Misconfiguration Check
- Verbose error messages
- Missing security headers
- Unnecessary HTTP methods enabled

## Report Example

### JSON Report
```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "timestamp": "2024-01-15T10:30:00",
  "summary": {
    "endpoints_scanned": 5,
    "checks_performed": 30,
    "vulnerabilities_found": 3
  },
  "alerts": [
    {
      "id": "alert-001",
      "vulnerability": {
        "type": "sql_injection",
        "severity": "critical",
        "confidence": 0.85,
        "endpoint": "/api/users",
        "evidence": "SQL injection detected with payload: ' OR '1'='1"
      },
      "remediation": {
        "steps": [
          "Use parameterized queries or prepared statements",
          "Implement input validation and sanitization"
        ],
        "owasp_mapping": "API8:2023 Security Misconfiguration"
      }
    }
  ]
}
```

## False Positive Management

```python
# Load false positives database
scanner.load_false_positives('false_positives.json')

# Run scan
report = scanner.scan()

# Mark an alert as false positive
if report.alerts:
    scanner.mark_false_positive(
        report.alerts[0],
        marked_by='security_team@example.com'
    )

# Save updated database
scanner.save_false_positives('false_positives.json')
```

## Best Practices

1. **Always get authorization** before scanning any API
2. **Start with dry-run mode** to understand what will be tested
3. **Use read-only mode** for production systems
4. **Enable request throttling** to avoid overwhelming the target
5. **Review false positives** regularly to improve accuracy
6. **Test in staging** environments first
7. **Monitor scan logs** for any issues
8. **Keep the scanner updated** with latest security checks

## Ethical Usage

This tool is designed for **ethical security testing only**. You must:

- ✅ Have explicit permission to test the target API
- ✅ Use it for authorized security assessments
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and system resources
- ❌ Never use it for unauthorized access
- ❌ Never use it to harm or disrupt services
- ❌ Never use it for illegal activities

## OWASP API Security Top 10 Coverage

This scanner helps detect vulnerabilities from the OWASP API Security Top 10:

- API1:2023 Broken Object Level Authorization
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization
- API4:2023 Unrestricted Resource Consumption
- API5:2023 Broken Function Level Authorization
- API8:2023 Security Misconfiguration

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any system.

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/yourusername/api-vulnerability-scanner/issues
- Documentation: https://github.com/yourusername/api-vulnerability-scanner/wiki

## Acknowledgments

- OWASP API Security Project
- Security research community
- All contributors

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
