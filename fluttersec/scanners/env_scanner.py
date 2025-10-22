"""
Scanner for .env files and environment variable leakage
"""
from pathlib import Path
from typing import List
from ..models import Finding, Severity, Remediation


class EnvScanner:
    """Scan for exposed .env files and environment variables"""

    SENSITIVE_FILES = [
        '.env',
        '.env.production',
        '.env.development',
        '.env.local',
        '.env.staging',
        'config.json',
        'secrets.json',
        'credentials.json',
    ]

    def __init__(self):
        self.findings: List[Finding] = []

    def scan(self, extract_dir: Path) -> List[Finding]:
        """Scan directory for environment files"""
        self.findings = []

        # Check flutter_assets directory
        flutter_assets = extract_dir / "assets" / "flutter_assets"
        if not flutter_assets.exists():
            # iOS path
            flutter_assets = extract_dir / "Payload"
            if flutter_assets.exists():
                app_dirs = list(flutter_assets.glob("*.app"))
                if app_dirs:
                    flutter_assets = app_dirs[0] / "Frameworks" / "App.framework" / "flutter_assets"

        if flutter_assets.exists():
            self._scan_directory(flutter_assets)

        # Also scan root assets directory
        assets_dir = extract_dir / "assets"
        if assets_dir.exists():
            self._scan_directory(assets_dir)

        return self.findings

    def _scan_directory(self, directory: Path) -> None:
        """Scan a specific directory for sensitive files"""
        for pattern in self.SENSITIVE_FILES:
            for file_path in directory.rglob(pattern):
                if file_path.is_file():
                    self._analyze_env_file(file_path, directory)

    def _analyze_env_file(self, file_path: Path, base_dir: Path) -> None:
        """Analyze a found .env or config file"""
        try:
            content = file_path.read_text()
            relative_path = file_path.relative_to(base_dir.parent.parent if "flutter_assets" in str(file_path) else base_dir.parent)

            # Extract sensitive patterns
            sensitive_keys = self._extract_sensitive_keys(content)

            remediation = Remediation(
                summary="Remove .env file from production builds",
                root_cause=f"The file '{file_path.name}' was included in pubspec.yaml assets section",
                why_wrong=(
                    "Flutter bundles all assets directly into the APK/IPA. "
                    "Anyone can extract the file using simple unzip command. "
                    "This exposes all API endpoints, keys, and sensitive configuration."
                ),
                fix_steps=[
                    "1. Remove .env from pubspec.yaml assets section",
                    "2. Create lib/core/config/app_config.dart with compile-time constants",
                    "3. Replace dotenv.env['KEY'] with AppConfig.key",
                    "4. Rebuild: flutter clean && flutter build apk --release",
                    "5. Verify: Re-scan with fluttersec to confirm .env is removed"
                ],
                code_before="""# pubspec.yaml
flutter:
  assets:
    - .env  # ❌ EXPOSED in production build""",
                code_after="""# pubspec.yaml
flutter:
  assets:
    # - .env  # ✅ REMOVED for security

# lib/core/config/app_config.dart
class AppConfig {
  static const baseUrl = 'https://api.example.com';
  static const apiPrefix = '/api/v1';

  static String get apiBaseUrl => '$baseUrl$apiPrefix';
}""",
                verification="Run: fluttersec scan app-release.apk\nExpected: No .env findings",
                references=[
                    "https://owasp.org/www-project-mobile-top-10/",
                    "https://docs.flutter.dev/deployment/obfuscate"
                ]
            )

            finding = Finding(
                severity=Severity.CRITICAL,
                title=f"{file_path.name} File Exposed",
                description=(
                    f"Environment configuration file found at '{relative_path}'. "
                    f"This file is completely unprotected and can be extracted in < 30 seconds. "
                    f"Found {len(sensitive_keys)} sensitive keys: {', '.join(sensitive_keys[:5])}"
                    f"{'...' if len(sensitive_keys) > 5 else ''}"
                ),
                file_path=str(relative_path),
                remediation=remediation,
                owasp="M9: Reverse Engineering",
                cwe="CWE-312: Cleartext Storage of Sensitive Information",
                cvss_score=9.1
            )

            self.findings.append(finding)

        except Exception as e:
            # Log error but don't fail
            pass

    def _extract_sensitive_keys(self, content: str) -> List[str]:
        """Extract sensitive key names from file content"""
        keys = []
        for line in content.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key = line.split('=')[0].strip()
                if key and self._is_sensitive_key(key):
                    keys.append(key)
        return keys

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key name suggests sensitive data"""
        sensitive_patterns = [
            'api', 'key', 'secret', 'token', 'password', 'auth',
            'url', 'endpoint', 'host', 'server', 'id', 'credential'
        ]
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in sensitive_patterns)
