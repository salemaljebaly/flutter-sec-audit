"""
Data models for security findings and analysis results
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Platform(Enum):
    """Mobile platform types"""
    ANDROID = "Android"
    IOS = "iOS"
    UNKNOWN = "Unknown"


@dataclass
class Remediation:
    """Fix instructions for a vulnerability"""
    summary: str
    root_cause: str
    why_wrong: str
    fix_steps: List[str]
    code_before: Optional[str] = None
    code_after: Optional[str] = None
    verification: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """A security vulnerability finding"""
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation: Optional[Remediation] = None
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export"""
        return {
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'owasp': self.owasp,
            'cwe': self.cwe,
            'cvss_score': self.cvss_score,
            'remediation': {
                'summary': self.remediation.summary,
                'root_cause': self.remediation.root_cause,
                'why_wrong': self.remediation.why_wrong,
                'fix_steps': self.remediation.fix_steps,
                'code_before': self.remediation.code_before,
                'code_after': self.remediation.code_after,
                'verification': self.remediation.verification,
                'references': self.remediation.references,
            } if self.remediation else None
        }


@dataclass
class AttackProfile:
    """Simulated attacker profile"""
    level: str  # beginner, intermediate, advanced
    time_minutes: int
    success_rate: float
    tools: List[str]
    capabilities: List[str]


@dataclass
class AnalysisResult:
    """Complete analysis result for an app"""
    app_name: str
    package_name: str
    platform: Platform
    file_path: str
    flutter_version: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    security_score: int = 100
    grade: str = "A"
    attack_surface_score: int = 0
    time_to_compromise_minutes: int = 0
    attacker_profile: Optional[AttackProfile] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results"""
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity"""
        return [f for f in self.findings if f.severity == severity]

    def count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export"""
        return {
            'app_name': self.app_name,
            'package_name': self.package_name,
            'platform': self.platform.value,
            'file_path': self.file_path,
            'flutter_version': self.flutter_version,
            'security_score': self.security_score,
            'grade': self.grade,
            'attack_surface_score': self.attack_surface_score,
            'time_to_compromise_minutes': self.time_to_compromise_minutes,
            'timestamp': self.timestamp.isoformat(),
            'findings_count': self.count_by_severity(),
            'findings': [f.to_dict() for f in self.findings],
        }
