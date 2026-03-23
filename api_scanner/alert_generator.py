"""
Alert Generator for creating security alerts with remediation guidance.
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List
from .models import (
    Vulnerability,
    Alert,
    RemediationGuidance,
    OWASP_API_MAPPING
)

logger = logging.getLogger(__name__)


class AlertGenerator:
    """Generates security alerts with remediation guidance"""
    
    # Remediation guidance for each vulnerability type
    REMEDIATION_GUIDES: Dict[str, RemediationGuidance] = {
        'sql_injection': RemediationGuidance(
            steps=[
                'Use parameterized queries or prepared statements',
                'Implement input validation and sanitization',
                'Use ORM frameworks that handle SQL escaping',
                'Apply principle of least privilege to database accounts',
                'Enable SQL injection detection in WAF'
            ],
            references=[
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            ],
            owasp_mapping='API8:2023 Security Misconfiguration'
        ),
        'nosql_injection': RemediationGuidance(
            steps=[
                'Validate and sanitize all user input',
                'Use parameterized queries with NoSQL databases',
                'Implement strict input type checking',
                'Avoid using user input directly in queries',
                'Enable NoSQL injection protection in WAF'
            ],
            references=[
                'https://owasp.org/www-community/attacks/NoSQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
            ],
            owasp_mapping='API8:2023 Security Misconfiguration'
        ),
        'command_injection': RemediationGuidance(
            steps=[
                'Avoid executing system commands with user input',
                'Use safe APIs that don\'t invoke shell',
                'Implement strict input validation with allowlists',
                'Escape shell metacharacters if commands are necessary',
                'Run application with minimal privileges'
            ],
            references=[
                'https://owasp.org/www-community/attacks/Command_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
            ],
            owasp_mapping='API8:2023 Security Misconfiguration'
        ),
        'authentication_bypass': RemediationGuidance(
            steps=[
                'Implement proper authentication checks on all protected endpoints',
                'Use established authentication frameworks',
                'Validate authentication tokens on every request',
                'Implement multi-factor authentication',
                'Log and monitor authentication failures'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
            ],
            owasp_mapping='API2:2023 Broken Authentication'
        ),
        'weak_authentication': RemediationGuidance(
            steps=[
                'Enforce strong password policies',
                'Disable default credentials',
                'Implement account lockout after failed attempts',
                'Use secure password hashing (bcrypt, Argon2)',
                'Require password changes for default accounts'
            ],
            references=[
                'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
                'https://pages.nist.gov/800-63-3/sp800-63b.html'
            ],
            owasp_mapping='API2:2023 Broken Authentication'
        ),
        'idor': RemediationGuidance(
            steps=[
                'Implement proper authorization checks for all resources',
                'Use indirect object references (random IDs)',
                'Validate user permissions before returning data',
                'Implement access control lists (ACLs)',
                'Log and monitor unauthorized access attempts'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'
            ],
            owasp_mapping='API1:2023 Broken Object Level Authorization'
        ),
        'privilege_escalation': RemediationGuidance(
            steps=[
                'Implement function-level authorization checks',
                'Validate user roles on every privileged operation',
                'Use role-based access control (RBAC)',
                'Never trust client-side role information',
                'Audit and log privilege changes'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
            ],
            owasp_mapping='API5:2023 Broken Function Level Authorization'
        ),
        'sensitive_data_exposure': RemediationGuidance(
            steps=[
                'Encrypt sensitive data at rest and in transit',
                'Implement data classification policies',
                'Remove sensitive data from API responses',
                'Use field-level encryption for PII',
                'Implement data masking for logs and errors'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
            ],
            owasp_mapping='API3:2023 Broken Object Property Level Authorization'
        ),
        'missing_https': RemediationGuidance(
            steps=[
                'Enforce HTTPS for all endpoints',
                'Redirect HTTP requests to HTTPS',
                'Implement HSTS (HTTP Strict Transport Security)',
                'Use valid SSL/TLS certificates',
                'Disable insecure protocols (TLS 1.0, 1.1)'
            ],
            references=[
                'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
                'https://https.cio.gov/'
            ],
            owasp_mapping='API8:2023 Security Misconfiguration'
        ),
        'missing_rate_limit': RemediationGuidance(
            steps=[
                'Implement rate limiting on all API endpoints',
                'Use token bucket or sliding window algorithms',
                'Return 429 status code when limit exceeded',
                'Include rate limit headers in responses',
                'Implement different limits for authenticated vs anonymous users'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html'
            ],
            owasp_mapping='API4:2023 Unrestricted Resource Consumption'
        ),
        'verbose_errors': RemediationGuidance(
            steps=[
                'Implement custom error pages',
                'Log detailed errors server-side only',
                'Return generic error messages to clients',
                'Remove stack traces from production responses',
                'Disable debug mode in production'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html'
            ],
            owasp_mapping='API8:2023 Security Misconfiguration'
        ),
        'missing_security_headers': RemediationGuidance(
            steps=[
                'Implement all recommended security headers',
                'Set Strict-Transport-Security header',
                'Set X-Content-Type-Options: nosniff',
                'Set X-Frame-Options: DENY or SAMEORIGIN',
                'Implement Content-Security-Policy'
            ],
            references=[
                'https://owasp.org/www-project-secure-headers/',
                'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
            ],
            owasp_mapping='API8:2023 Security Misconfiguration'
        ),
    }
    
    def generate_alert(self, vulnerability: Vulnerability) -> Alert:
        """Create alert with remediation guidance"""
        alert_id = str(uuid.uuid4())
        remediation = self.get_remediation_guidance(vulnerability.type)
        
        # Flag for manual verification if confidence is low
        requires_verification = vulnerability.confidence < 0.6
        
        alert = Alert(
            id=alert_id,
            vulnerability=vulnerability,
            remediation=remediation,
            timestamp=datetime.now(),
            requires_manual_verification=requires_verification
        )
        
        logger.info(f"Generated alert {alert_id} for {vulnerability.type} at {vulnerability.endpoint}")
        return alert
    
    def get_remediation_guidance(self, vulnerability_type: str) -> RemediationGuidance:
        """Retrieve remediation steps for vulnerability type"""
        if vulnerability_type in self.REMEDIATION_GUIDES:
            return self.REMEDIATION_GUIDES[vulnerability_type]
        
        # Default remediation guidance
        owasp_mapping = OWASP_API_MAPPING.get(vulnerability_type, 'API8:2023 Security Misconfiguration')
        
        return RemediationGuidance(
            steps=[
                'Review and fix the identified vulnerability',
                'Implement security best practices',
                'Test the fix thoroughly',
                'Monitor for similar issues'
            ],
            references=[
                'https://owasp.org/www-project-api-security/',
                'https://cheatsheetseries.owasp.org/'
            ],
            owasp_mapping=owasp_mapping
        )
    
    def map_to_owasp(self, vulnerability_type: str) -> str:
        """Map vulnerability to OWASP API Security Top 10"""
        return OWASP_API_MAPPING.get(vulnerability_type, 'API8:2023 Security Misconfiguration')
