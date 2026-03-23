from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import logging
import uuid
import json
from datetime import datetime
import requests
from api_scanner import VulnerabilityScanner, ScanConfiguration, SeverityLevel


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
CORS(app)

# ASI Agent API Configuration
ASI_API_KEY = "sk_77827d0f9d9649699bdd789844da4699adbc520bf44b4808ad25c5524e12e295"
ASI_API_URL = "https://api.asi1.ai/v1/chat/completions"


scan_results = {}


@app.route('/')
def index():
    """Render the main chatbot interface"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def scan_api():
    """Scan an API for vulnerabilities"""
    try:
        data = request.json
        api_url = data.get('api_url', '').strip()
        endpoints = data.get('endpoints', [])

        if not api_url:
            return jsonify({'error': 'API URL is required'}), 400

        # Default endpoints if none provided
        if not endpoints:
            endpoints = ['/', '/api', '/login', '/auth', '/register', '/users']

        logger.info(f"Starting scan for {api_url}")

        # Create scan configuration
        config = ScanConfiguration(
            base_url=api_url,
            endpoints=endpoints,
            severity_threshold=SeverityLevel.INFO,
            dry_run=False,
            request_throttle_ms=100,
            verbose_logging=False
        )

        
        scanner = VulnerabilityScanner(config)

        
        report = scanner.scan()

        
        scan_id = str(uuid.uuid4())

        
        report_data = {
            'scan_id': scan_id,
            'timestamp': report.timestamp.isoformat(),
            'api_url': api_url,
            'endpoints_scanned': report.endpoints_scanned,
            'checks_performed': report.checks_performed,
            'vulnerabilities_found': len(report.alerts),
            'scan_duration': report.scan_duration.total_seconds(),
            'alerts': []
        }

       
        seen_types = {}

        for alert in report.alerts:
            vuln_type = alert.vulnerability.type
            if vuln_type not in seen_types:
                seen_types[vuln_type] = {
                    'id': alert.id,
                    'type': vuln_type,
                    'severity': alert.vulnerability.severity.value,
                    'confidence': alert.vulnerability.confidence,
                    'endpoint': alert.vulnerability.endpoint,
                    'evidence': alert.vulnerability.evidence,
                    'owasp_mapping': alert.remediation.owasp_mapping,
                    'remediation_steps': alert.remediation.steps,
                    'references': alert.remediation.references,
                    'requires_verification': alert.requires_manual_verification,
                    'affected_endpoints': [alert.vulnerability.endpoint]
                }
            else:
                ep = alert.vulnerability.endpoint
                if ep not in seen_types[vuln_type]['affected_endpoints']:
                    seen_types[vuln_type]['affected_endpoints'].append(ep)

        unique_alerts = list(seen_types.values())

        report_data['alerts'] = unique_alerts
        report_data['vulnerabilities_found'] = len(unique_alerts)

        
        scan_results[scan_id] = report_data

        logger.info(f"Scan completed: {scan_id}, found {len(unique_alerts)} unique vulnerabilities")

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'report': report_data
        })

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/chat', methods=['POST'])
def chat():
    """Chat with AI about vulnerability report"""
    try:
        data = request.json
        message = data.get('message', '').strip()
        scan_id = data.get('scan_id')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        
        report_context = ""
        if scan_id and scan_id in scan_results:
            report = scan_results[scan_id]
            report_context = f"""
Scan Report Context:
- API URL: {report['api_url']}
- Endpoints Scanned: {report['endpoints_scanned']}
- Vulnerabilities Found: {report['vulnerabilities_found']}
- Scan Duration: {report['scan_duration']:.1f} seconds

Vulnerabilities:
"""
            for alert in report['alerts']:
                report_context += f"""
- {alert['type'].replace('_', ' ').title()}
  Severity: {alert['severity'].upper()}
  Endpoint: {alert['endpoint']}
  Evidence: {alert['evidence']}
  OWASP: {alert['owasp_mapping']}
"""

        
        response = call_asi_agent(message, report_context)

        return jsonify({
            'success': True,
            'response': response
        })

    except Exception as e:
        logger.error(f"Chat failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def call_asi_agent(user_message, context=""):
    """Call ASI Agent API for chat response"""
    try:
        system_prompt = """You are a cybersecurity expert assistant helping users understand API vulnerability scan reports.
You provide clear, actionable advice on security vulnerabilities, their risks, and how to fix them.
Be concise, professional, and helpful. Use simple language when explaining technical concepts."""

        if context:
            system_prompt += f"\n\nCurrent Scan Report:\n{context}"

        headers = {
            'Authorization': f'Bearer {ASI_API_KEY}',
            'Content-Type': 'application/json'
        }

        payload = {
            'model': 'asi1-mini',
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message}
            ],
            'temperature': 0.7,
            'max_tokens': 500
        }

        response = requests.post(ASI_API_URL, headers=headers, json=payload, timeout=30)

        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            logger.error(f"ASI API error: {response.status_code} - {response.text}")
            return generate_fallback_response(user_message, context)

    except Exception as e:
        logger.error(f"ASI API call failed: {e}")
        return generate_fallback_response(user_message, context)


def generate_fallback_response(user_message, context):
    """Generate a fallback response when ASI API is unavailable"""
    message_lower = user_message.lower()

    if 'sql injection' in message_lower or 'injection' in message_lower:
        return """SQL Injection is a critical vulnerability where attackers can manipulate database queries.

To fix:
1. Use parameterized queries/prepared statements
2. Validate and sanitize all user input
3. Use ORM frameworks that handle SQL escaping
4. Apply principle of least privilege to database accounts

This is a CRITICAL severity issue and should be fixed immediately."""

    elif 'authentication' in message_lower or 'auth' in message_lower:
        return """Authentication vulnerabilities allow unauthorized access to your API.

Common issues:
- Missing authentication on protected endpoints
- Weak authentication schemes
- Default credentials
- Token expiration issues

Fix by:
1. Implement proper authentication on all protected endpoints
2. Use strong authentication mechanisms (OAuth2, JWT)
3. Disable default credentials
4. Implement proper session management"""

    elif 'https' in message_lower or 'ssl' in message_lower or 'tls' in message_lower:
        return """Missing HTTPS is a HIGH severity issue. All API traffic should be encrypted.

To fix:
1. Enforce HTTPS for all endpoints
2. Redirect HTTP requests to HTTPS
3. Implement HSTS (HTTP Strict Transport Security)
4. Use valid SSL/TLS certificates
5. Disable insecure protocols (TLS 1.0, 1.1)"""

    elif 'rate limit' in message_lower:
        return """Rate limiting protects your API from abuse and DoS attacks.

To implement:
1. Add rate limiting middleware to your API
2. Use token bucket or sliding window algorithms
3. Return 429 status code when limit exceeded
4. Include rate limit headers in responses
5. Implement different limits for authenticated vs anonymous users"""

    elif 'how to fix' in message_lower or 'remediation' in message_lower:
        return """To fix vulnerabilities:

1. Review the scan report and prioritize by severity (Critical > High > Medium > Low)
2. Start with Critical and High severity issues
3. Follow the remediation steps provided for each vulnerability
4. Test your fixes thoroughly
5. Re-scan to verify vulnerabilities are resolved
6. Implement security best practices going forward

Need help with a specific vulnerability? Ask me about it!"""

    else:
        return """I'm here to help you understand the vulnerability scan report and how to secure your API.

You can ask me about:
- Specific vulnerabilities (SQL injection, authentication issues, etc.)
- How to fix security issues
- Security best practices
- OWASP API Security guidelines
- Prioritizing vulnerabilities

What would you like to know?"""


@app.route('/api/report/<scan_id>')
def get_report(scan_id):
    """Get scan report by ID"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Scan not found'}), 404


if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("API Vulnerability Scanner - Web Application")
    print("=" * 80)
    print("\nStarting web server...")
    print("Open your browser and go to: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 80 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
