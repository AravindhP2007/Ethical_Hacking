# Quick Start Guide

Get started with the API Vulnerability Scanner in 5 minutes!

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Run Your First Scan

### Option A: Use the Simple Script

```bash
python .vscode/hacking.py
```

This will scan a public test API and show you how the scanner works.

### Option B: Use the CLI

```bash
# Scan a specific API
python cli.py https://jsonplaceholder.typicode.com --endpoints /posts /users

# See all options
python cli.py --help
```

### Option C: Use Python Code

```python
from api_scanner import VulnerabilityScanner, ScanConfiguration

# Configure the scan
config = ScanConfiguration(
    base_url='https://api.example.com',
    endpoints=['/api/users', '/api/products'],
    dry_run=False  # Set to True to simulate
)

# Run the scan
scanner = VulnerabilityScanner(config)
report = scanner.scan()

# Export results
scanner.export_report(report, 'report.json', 'json')
scanner.export_report(report, 'report.html', 'html')

# Print summary
print(f"Found {len(report.alerts)} vulnerabilities")
```

## Step 3: Review the Results

The scanner will generate:
- **JSON report**: Machine-readable format for automation
- **HTML report**: Human-readable format with styling
- **Console output**: Real-time progress and summary

## Step 4: Understand the Alerts

Each alert includes:
- **Vulnerability Type**: What was found (e.g., SQL injection)
- **Severity**: Critical, High, Medium, Low, or Info
- **Confidence**: How certain the scanner is (0-100%)
- **Evidence**: What triggered the alert
- **Remediation Steps**: How to fix the issue
- **OWASP Mapping**: Related OWASP API Security category

## Common Use Cases

### 1. Quick Security Check

```bash
python cli.py https://api.example.com --endpoints /api/users --dry-run
```

### 2. Comprehensive Scan

```bash
python cli.py https://api.example.com \
  --endpoints /api/users /api/products /api/orders \
  --format all \
  --severity medium
```

### 3. Automated Testing

```python
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel

config = ScanConfiguration(
    base_url='https://api.example.com',
    endpoints=['/api/users'],
    severity_threshold=SeverityLevel.HIGH
)

scanner = VulnerabilityScanner(config)
report = scanner.scan()

# Fail CI/CD if critical vulnerabilities found
if any(a.vulnerability.severity.value == 'critical' for a in report.alerts):
    print("❌ Critical vulnerabilities found!")
    exit(1)
```

### 4. Custom Security Checks

```python
config = ScanConfiguration(
    base_url='https://api.example.com',
    endpoints=['/api/users'],
    security_checks=[
        'authentication_check',
        'injection_check',
        'sensitive_data_check'
    ]
)
```

## Configuration File

Create `scan_config.json`:

```json
{
  "base_url": "https://api.example.com",
  "endpoints": ["/api/users", "/api/products"],
  "severity_threshold": "medium",
  "dry_run": false,
  "request_throttle_ms": 100
}
```

Then use it:

```bash
python cli.py --config scan_config.json
```

## Tips for Best Results

1. **Start with dry-run**: Test without actual requests first
   ```bash
   python cli.py https://api.example.com --endpoints /api/users --dry-run
   ```

2. **Use throttling**: Be respectful to the target API
   ```bash
   python cli.py https://api.example.com --endpoints /api/users --throttle 200
   ```

3. **Filter by severity**: Focus on critical issues first
   ```bash
   python cli.py https://api.example.com --endpoints /api/users --severity high
   ```

4. **Review HTML reports**: Easier to read than JSON
   ```bash
   python cli.py https://api.example.com --endpoints /api/users --format html
   ```

5. **Manage false positives**: Mark and exclude known false positives
   ```python
   scanner.load_false_positives('false_positives.json')
   # ... run scan ...
   scanner.mark_false_positive(alert, marked_by='security_team')
   scanner.save_false_positives('false_positives.json')
   ```

## Testing the Scanner

Run the test suite to verify everything works:

```bash
python test_scanner.py
```

This will:
1. Run a dry-run test (no actual requests)
2. Optionally run a live test against a public API
3. Generate sample reports

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [example_usage.py](example_usage.py) for more examples
- Review the [security checks documentation](#security-checks)
- Learn about [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

## Getting Help

- Run `python cli.py --help` for CLI options
- Check the examples in `example_usage.py`
- Review the code documentation in each module
- Open an issue on GitHub for bugs or questions

## Important Reminders

⚠️ **Always get authorization before scanning any API**

✅ Use for ethical security testing only

✅ Test in staging environments first

✅ Be respectful with request rates

✅ Follow responsible disclosure practices

---

Happy scanning! 🔒🔍
