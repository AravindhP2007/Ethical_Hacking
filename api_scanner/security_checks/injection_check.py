"""
Injection vulnerability detection.
"""

import logging
import requests
from urllib.parse import urljoin
from .base import SecurityCheck
from ..models import Endpoint, ScanConfiguration, CheckResult

logger = logging.getLogger(__name__)


class InjectionCheck(SecurityCheck):
    """Tests for injection vulnerabilities"""

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "1' AND SLEEP(2)--",
    ]

    COMMAND_PAYLOADS = [
        "; ls -la",
        "| whoami",
        "&& cat /etc/passwd",
    ]

    def check_name(self) -> str:
        return "injection_check"

    def execute(self, endpoint: Endpoint, config: ScanConfiguration) -> CheckResult:
        url = urljoin(config.base_url, endpoint.path)
        vulnerabilities = []

        sql_result = self._test_sql_injection(url, config)
        if sql_result:
            vulnerabilities.append(sql_result)

        cmd_result = self._test_command_injection(url, config)
        if cmd_result:
            vulnerabilities.append(cmd_result)

        if vulnerabilities:
            return CheckResult(
                check_name=self.check_name(),
                endpoint=endpoint.path,
                vulnerable=True,
                evidence="; ".join(vulnerabilities)
            )

        return CheckResult(
            check_name=self.check_name(),
            endpoint=endpoint.path,
            vulnerable=False,
            evidence="No injection vulnerabilities detected"
        )

    def _test_sql_injection(self, url: str, config: ScanConfiguration) -> str:
        """Test for SQL injection by looking for database error messages in responses"""
        if config.dry_run:
            return ""
        try:
            # Get a baseline response first
            baseline = requests.get(url, headers=config.custom_headers, timeout=10)
            baseline_len = len(baseline.text)

            for payload in self.SQL_PAYLOADS:
                params = {'id': payload, 'search': payload, 'q': payload}
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)

                # Only flag on actual database error messages — not just any mention of SQL keywords
                db_error_patterns = [
                    'you have an error in your sql syntax',
                    'unclosed quotation mark',
                    'quoted string not properly terminated',
                    'pg::syntaxerror',
                    'ora-00933',
                    'microsoft ole db provider for sql server',
                    'sqlite3.operationalerror',
                    'psycopg2.errors',
                ]
                response_lower = response.text.lower()
                for pattern in db_error_patterns:
                    if pattern in response_lower:
                        logger.warning(f"SQL injection confirmed at {url} — DB error in response")
                        return f"SQL injection detected — database error message exposed with payload: {payload}"

        except requests.RequestException as e:
            logger.debug(f"Error testing SQL injection: {e}")
        return ""

    def _test_command_injection(self, url: str, config: ScanConfiguration) -> str:
        """Test for OS command injection by looking for shell output in responses"""
        if config.dry_run:
            return ""
        try:
            for payload in self.COMMAND_PAYLOADS:
                params = {'cmd': payload, 'exec': payload, 'command': payload}
                response = requests.get(url, params=params, headers=config.custom_headers, timeout=10)

                # Only flag on clear shell output indicators
                shell_output_indicators = ['root:x:0:0', 'uid=0(root)', 'uid=', 'gid=', '/bin/bash', '/bin/sh']
                for indicator in shell_output_indicators:
                    if indicator in response.text:
                        return f"Command injection detected — shell output in response with payload: {payload}"
        except requests.RequestException as e:
            logger.debug(f"Error testing command injection: {e}")
        return ""
