"""
Security scoring algorithm
"""
from typing import List, Dict
from ..models import Finding, Severity, AnalysisResult


class SecurityScorer:
    """Calculate security scores based on findings"""

    # Penalty points for each severity level
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0
    }

    def __init__(self):
        self.base_score = 100

    def calculate_score(self, findings: List[Finding]) -> int:
        """
        Calculate overall security score (0-100)
        Higher is better
        """
        penalty = 0

        for finding in findings:
            penalty += self.SEVERITY_WEIGHTS.get(finding.severity, 0)

        # Calculate score
        score = max(0, self.base_score - penalty)
        return score

    def get_grade(self, score: int) -> str:
        """Convert score to letter grade"""
        if score >= 90:
            return "A (Excellent)"
        elif score >= 75:
            return "B (Good)"
        elif score >= 60:
            return "C (Fair)"
        elif score >= 40:
            return "D (Poor)"
        else:
            return "F (Critical)"

    def calculate_attack_surface(self, findings: List[Finding]) -> int:
        """
        Calculate attack surface score (0-10)
        Higher means more vulnerable
        """
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        # Attack surface increases with critical and high findings
        attack_surface = min(10, (critical_count * 2) + high_count)

        return attack_surface

    def get_risk_level(self, score: int) -> str:
        """Get risk level description"""
        if score >= 80:
            return "Low Risk"
        elif score >= 60:
            return "Medium Risk"
        elif score >= 40:
            return "High Risk"
        else:
            return "Critical Risk"

    def get_priority_findings(self, findings: List[Finding], limit: int = 5) -> List[Finding]:
        """Get top priority findings to fix first"""
        # Sort by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }

        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity, 99)
        )

        return sorted_findings[:limit]

    def analyze_security_posture(self, result: AnalysisResult) -> Dict[str, any]:
        """Comprehensive security posture analysis"""
        findings_count = result.count_by_severity()

        analysis = {
            'score': result.security_score,
            'grade': result.grade,
            'risk_level': self.get_risk_level(result.security_score),
            'attack_surface': result.attack_surface_score,
            'findings_breakdown': findings_count,
            'total_findings': len(result.findings),
            'critical_issues': findings_count.get('CRITICAL', 0),
            'needs_immediate_attention': findings_count.get('CRITICAL', 0) > 0,
            'priority_fixes': [f.title for f in self.get_priority_findings(result.findings, 3)],
        }

        # Add recommendations
        if findings_count.get('CRITICAL', 0) > 0:
            analysis['recommendation'] = "⚠️ URGENT: Fix critical issues immediately before production release"
        elif findings_count.get('HIGH', 0) > 0:
            analysis['recommendation'] = "Fix high severity issues within 1 week"
        elif findings_count.get('MEDIUM', 0) > 0:
            analysis['recommendation'] = "Address medium issues in next sprint"
        else:
            analysis['recommendation'] = "✅ Good security posture! Continue monitoring"

        return analysis

    def compare_scores(self, before_result: AnalysisResult, after_result: AnalysisResult) -> Dict:
        """Compare two analysis results (before/after fixes)"""
        improvement = after_result.security_score - before_result.security_score

        before_counts = before_result.count_by_severity()
        after_counts = after_result.count_by_severity()

        comparison = {
            'score_improvement': improvement,
            'before_score': before_result.security_score,
            'after_score': after_result.security_score,
            'before_grade': before_result.grade,
            'after_grade': after_result.grade,
            'fixed_critical': before_counts.get('CRITICAL', 0) - after_counts.get('CRITICAL', 0),
            'fixed_high': before_counts.get('HIGH', 0) - after_counts.get('HIGH', 0),
            'fixed_total': len(before_result.findings) - len(after_result.findings),
            'status': 'improved' if improvement > 0 else 'worse' if improvement < 0 else 'unchanged'
        }

        return comparison
