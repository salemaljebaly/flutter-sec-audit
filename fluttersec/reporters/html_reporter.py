"""
HTML report generator with beautiful styling
"""
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime
from ..models import AnalysisResult, Severity


class HTMLReporter:
    """Generate beautiful HTML reports"""

    def generate(self, result: AnalysisResult, output_path: str, attack_result: Optional[Dict] = None) -> None:
        """Generate HTML report"""
        html = self._generate_html(result, attack_result)

        output_file = Path(output_path)
        output_file.write_text(html)

    def _generate_html(self, result: AnalysisResult, attack_result: Optional[Dict]) -> str:
        """Generate complete HTML document"""
        counts = result.count_by_severity()

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {result.app_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h3 {{ color: #555; margin-top: 20px; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .metadata {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 30px; }}
        .metadata div {{ margin: 5px 0; }}
        .score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .score-number {{ font-size: 48px; font-weight: bold; }}
        .grade {{ font-size: 24px; margin-top: 10px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .critical-card {{ background: #fee; border-left: 4px solid #e74c3c; }}
        .high-card {{ background: #fff3cd; border-left: 4px solid #f39c12; }}
        .medium-card {{ background: #fffbea; border-left: 4px solid #f1c40f; }}
        .low-card {{ background: #e3f2fd; border-left: 4px solid #3498db; }}
        .summary-card .count {{ font-size: 36px; font-weight: bold; }}
        .summary-card .label {{ font-size: 14px; text-transform: uppercase; color: #666; margin-top: 5px; }}
        .finding {{
            background: white;
            border: 1px solid #ddd;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .finding.critical {{ border-left-color: #e74c3c; }}
        .finding.high {{ border-left-color: #f39c12; }}
        .finding.medium {{ border-left-color: #f1c40f; }}
        .finding.low {{ border-left-color: #3498db; }}
        .finding-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
        .finding-description {{ margin-bottom: 15px; color: #555; }}
        .finding-meta {{ background: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 15px; font-size: 14px; }}
        .remediation {{ background: #e8f5e9; padding: 15px; border-radius: 5px; border-left: 3px solid #4caf50; }}
        .remediation-title {{ font-weight: bold; color: #2e7d32; margin-bottom: 10px; }}
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }}
        .attack-sim {{
            background: #fff3cd;
            border-left: 4px solid #f39c12;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .attack-timeline {{ margin-top: 15px; }}
        .attack-step {{ margin: 8px 0; padding-left: 20px; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin: 0 5px;
        }}
        .badge-critical {{ background: #e74c3c; color: white; }}
        .badge-high {{ background: #f39c12; color: white; }}
        .badge-medium {{ background: #f1c40f; color: #333; }}
        .badge-low {{ background: #3498db; color: white; }}
        .footer {{ text-align: center; margin-top: 40px; color: #999; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 FlutterSecAudit Security Report</h1>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="metadata">
            <div><strong>App Name:</strong> {result.app_name}</div>
            <div><strong>Package:</strong> {result.package_name}</div>
            <div><strong>Platform:</strong> {result.platform.value}</div>
            <div><strong>File:</strong> {result.file_path}</div>
        </div>

        <div class="score-card">
            <div class="score-number">{result.security_score}/100</div>
            <div class="grade">{result.grade}</div>
        </div>

        <h2>📊 Findings Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical-card">
                <div class="count">{counts.get('CRITICAL', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high-card">
                <div class="count">{counts.get('HIGH', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium-card">
                <div class="count">{counts.get('MEDIUM', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low-card">
                <div class="count">{counts.get('LOW', 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>
"""

        # Attack simulation section
        if attack_result:
            html += f"""
        <h2>⚔️ Attack Simulation</h2>
        <div class="attack-sim">
            <div><strong>⏱️ Time to Compromise:</strong> {attack_result['overall_time_to_compromise']} minutes</div>
            <div><strong>👤 Most Likely Attacker:</strong> {attack_result['most_likely_attacker'].title()}</div>

            <div class="attack-timeline">
                <strong>Attack Scenario:</strong>
"""
            for step in attack_result['attack_scenario']:
                html += f"                <div class='attack-step'>{step}</div>\n"

            html += """
            </div>
        </div>
"""

        # Detailed findings
        if result.findings:
            html += "        <h2>🔍 Detailed Findings</h2>\n"

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                severity_findings = result.get_findings_by_severity(severity)
                if not severity_findings:
                    continue

                for finding in severity_findings:
                    severity_class = severity.value.lower()
                    html += f"""
        <div class="finding {severity_class}">
            <div class="finding-title">
                <span class="badge badge-{severity_class}">{severity.value}</span>
                {finding.title}
            </div>
            <div class="finding-description">{finding.description}</div>
"""

                    if finding.file_path or finding.owasp or finding.cwe:
                        html += "            <div class='finding-meta'>\n"
                        if finding.file_path:
                            html += f"                <div><strong>Location:</strong> <code>{finding.file_path}</code></div>\n"
                        if finding.owasp:
                            html += f"                <div><strong>OWASP:</strong> {finding.owasp}</div>\n"
                        if finding.cwe:
                            html += f"                <div><strong>CWE:</strong> {finding.cwe}</div>\n"
                        html += "            </div>\n"

                    if finding.remediation:
                        html += f"""
            <div class="remediation">
                <div class="remediation-title">✅ How to Fix</div>
                <p><strong>{finding.remediation.summary}</strong></p>
                <p><em>Why this is wrong:</em> {finding.remediation.why_wrong}</p>
"""
                        if finding.remediation.fix_steps:
                            html += "                <ol>\n"
                            for step in finding.remediation.fix_steps:
                                html += f"                    <li>{step}</li>\n"
                            html += "                </ol>\n"

                        if finding.remediation.code_before:
                            html += f"""
                <p><strong>Before (❌ Insecure):</strong></p>
                <div class="code-block">{finding.remediation.code_before}</div>
"""

                        if finding.remediation.code_after:
                            html += f"""
                <p><strong>After (✅ Secure):</strong></p>
                <div class="code-block">{finding.remediation.code_after}</div>
"""

                        html += "            </div>\n"

                    html += "        </div>\n"

        # Footer
        html += """
        <div class="footer">
            <p>Generated by <strong>FlutterSecAudit v0.1.0</strong></p>
            <p>Open source security scanner for Flutter apps</p>
        </div>
    </div>
</body>
</html>
"""

        return html
