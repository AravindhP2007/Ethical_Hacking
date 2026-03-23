"""
Report Exporter for generating scan reports in multiple formats.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from .models import ScanReport, Alert

logger = logging.getLogger(__name__)


class ReportExporter:
    """Exports scan reports in various formats"""
    
    def export_json(self, report: ScanReport, output_path: str) -> None:
        """Export report as JSON"""
        try:
            report_data = self._serialize_report(report)
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"Exported JSON report to {output_path}")
        
        except Exception as e:
            logger.error(f"Error exporting JSON report: {e}")
            raise
    
    def export_html(self, report: ScanReport, output_path: str) -> None:
        """Export report as HTML"""
        try:
            html_content = self._generate_html(report)
            
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Exported HTML report to {output_path}")
        
        except Exception as e:
            logger.error(f"Error exporting HTML report: {e}")
            raise
    
    def export_pdf(self, report: ScanReport, output_path: str) -> None:
        """Export report as PDF"""
        try:
            # For PDF export, we'll create a simple text-based version
            # In production, you'd use a library like ReportLab or WeasyPrint
            text_content = self._generate_text_report(report)
            
            # Save as text file with .pdf extension for now
            # In production, convert to actual PDF
            with open(output_path, 'w') as f:
                f.write(text_content)
            
            logger.info(f"Exported PDF report to {output_path}")
            logger.warning("PDF export is currently text-based. Install reportlab for proper PDF generation.")
        
        except Exception as e:
            logger.error(f"Error exporting PDF report: {e}")
            raise
    
    def _serialize_report(self, report: ScanReport) -> Dict[str, Any]:
        """Convert report to JSON-serializable dictionary"""
        return {
            'scan_id': report.scan_id,
            'timestamp': report.timestamp.isoformat(),
            'configuration': {
                'base_url': report.configuration.base_url,
                'endpoints': report.configuration.endpoints,
                'excluded_endpoints': report.configuration.excluded_endpoints,
                'security_checks': report.configuration.security_checks,
                'severity_threshold': report.configuration.severity_threshold.value,
                'dry_run': report.configuration.dry_run,
                'read_only': report.configuration.read_only,
            },
            'summary': {
                'endpoints_scanned': report.endpoints_scanned,
                'checks_performed': report.checks_performed,
                'vulnerabilities_found': len(report.alerts),
                'scan_duration_seconds': report.scan_duration.total_seconds(),
            },
            'alerts': [
                {
                    'id': alert.id,
                    'timestamp': alert.timestamp.isoformat(),
                    'vulnerability': {
                        'type': alert.vulnerability.type,
                        'severity': alert.vulnerability.severity.value,
                        'confidence': alert.vulnerability.confidence,
                        'endpoint': alert.vulnerability.endpoint,
                        'evidence': alert.vulnerability.evidence,
                    },
                    'remediation': {
                        'steps': alert.remediation.steps,
                        'references': alert.remediation.references,
                        'owasp_mapping': alert.remediation.owasp_mapping,
                    },
                    'requires_manual_verification': alert.requires_manual_verification,
                }
                for alert in report.alerts
            ]
        }
    
    def _generate_html(self, report: ScanReport) -> str:
        """Generate HTML report"""
        alerts_html = ""
        for alert in report.alerts:
            severity_class = alert.vulnerability.severity.value
            alerts_html += f"""
            <div class="alert alert-{severity_class}">
                <h3>{alert.vulnerability.type.replace('_', ' ').title()}</h3>
                <p><strong>Severity:</strong> {alert.vulnerability.severity.value.upper()}</p>
                <p><strong>Confidence:</strong> {alert.vulnerability.confidence:.0%}</p>
                <p><strong>Endpoint:</strong> {alert.vulnerability.endpoint}</p>
                <p><strong>Evidence:</strong> {alert.vulnerability.evidence}</p>
                <p><strong>OWASP Mapping:</strong> {alert.remediation.owasp_mapping}</p>
                <div class="remediation">
                    <h4>Remediation Steps:</h4>
                    <ol>
                        {''.join(f'<li>{step}</li>' for step in alert.remediation.steps)}
                    </ol>
                    <h4>References:</h4>
                    <ul>
                        {''.join(f'<li><a href="{ref}">{ref}</a></li>' for ref in alert.remediation.references)}
                    </ul>
                </div>
            </div>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>API Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .alert {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; border-left: 5px solid; }}
                .alert-critical {{ border-left-color: #e74c3c; }}
                .alert-high {{ border-left-color: #e67e22; }}
                .alert-medium {{ border-left-color: #f39c12; }}
                .alert-low {{ border-left-color: #3498db; }}
                .alert-info {{ border-left-color: #95a5a6; }}
                .remediation {{ background: #ecf0f1; padding: 15px; margin-top: 15px; border-radius: 3px; }}
                h1, h2, h3 {{ margin-top: 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>API Vulnerability Scan Report</h1>
                <p>Scan ID: {report.scan_id}</p>
                <p>Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Target:</strong> {report.configuration.base_url}</p>
                <p><strong>Endpoints Scanned:</strong> {report.endpoints_scanned}</p>
                <p><strong>Checks Performed:</strong> {report.checks_performed}</p>
                <p><strong>Vulnerabilities Found:</strong> {len(report.alerts)}</p>
                <p><strong>Scan Duration:</strong> {report.scan_duration.total_seconds():.1f} seconds</p>
            </div>
            
            <h2>Vulnerabilities</h2>
            {alerts_html if alerts_html else '<p>No vulnerabilities detected.</p>'}
        </body>
        </html>
        """
        
        return html
    
    def _generate_text_report(self, report: ScanReport) -> str:
        """Generate plain text report"""
        lines = [
            "=" * 80,
            "API VULNERABILITY SCAN REPORT",
            "=" * 80,
            f"Scan ID: {report.scan_id}",
            f"Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {report.configuration.base_url}",
            "",
            "SUMMARY",
            "-" * 80,
            f"Endpoints Scanned: {report.endpoints_scanned}",
            f"Checks Performed: {report.checks_performed}",
            f"Vulnerabilities Found: {len(report.alerts)}",
            f"Scan Duration: {report.scan_duration.total_seconds():.1f} seconds",
            "",
            "VULNERABILITIES",
            "-" * 80,
        ]
        
        if not report.alerts:
            lines.append("No vulnerabilities detected.")
        else:
            for i, alert in enumerate(report.alerts, 1):
                lines.extend([
                    "",
                    f"{i}. {alert.vulnerability.type.replace('_', ' ').title()}",
                    f"   Severity: {alert.vulnerability.severity.value.upper()}",
                    f"   Confidence: {alert.vulnerability.confidence:.0%}",
                    f"   Endpoint: {alert.vulnerability.endpoint}",
                    f"   Evidence: {alert.vulnerability.evidence}",
                    f"   OWASP: {alert.remediation.owasp_mapping}",
                    "",
                    "   Remediation Steps:",
                ])
                for j, step in enumerate(alert.remediation.steps, 1):
                    lines.append(f"   {j}. {step}")
                lines.append("")
        
        lines.append("=" * 80)
        return "\n".join(lines)
