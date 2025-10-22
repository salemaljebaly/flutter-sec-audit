"""
Scanner for exposed assets and sensitive files
"""
from pathlib import Path
from typing import List, Set
from ..models import Finding, Severity, Remediation


class AssetScanner:
    """Scan for exposed sensitive assets"""

    SENSITIVE_EXTENSIONS = {
        '.key', '.pem', '.p12', '.pfx', '.jks', '.keystore',
        '.db', '.sqlite', '.sqlite3', '.realm',
        '.json', '.xml', '.yaml', '.yml', '.toml', '.ini'
    }

    SENSITIVE_FILENAMES = {
        'google-services.json', 'GoogleService-Info.plist',
        'firebase_options.dart', 'secrets.dart',
        'config.json', 'settings.json', 'credentials.json',
        'database.db', 'app.db', 'user.db',
        'keystore.jks', 'key.jks', 'release.keystore'
    }

    WHITELISTED_PATTERNS = {
        'fontmanifest.json', 'assetmanifest.json',
        'kernel_blob.bin', 'isolate_snapshot'
    }

    def __init__(self):
        self.findings: List[Finding] = []

    def scan(self, extract_dir: Path) -> List[Finding]:
        """Scan for exposed assets"""
        self.findings = []

        # Scan flutter_assets
        self._scan_flutter_assets(extract_dir)

        # Scan root assets
        assets_dir = extract_dir / "assets"
        if assets_dir.exists():
            self._scan_directory(assets_dir, "assets")

        return self.findings

    def _scan_flutter_assets(self, extract_dir: Path) -> None:
        """Scan flutter_assets directory"""
        # Android path
        flutter_assets = extract_dir / "assets" / "flutter_assets"

        # iOS path
        if not flutter_assets.exists():
            payload = extract_dir / "Payload"
            if payload.exists():
                app_dirs = list(payload.glob("*.app"))
                if app_dirs:
                    flutter_assets = app_dirs[0] / "Frameworks" / "App.framework" / "flutter_assets"

        if flutter_assets.exists():
            self._scan_directory(flutter_assets, "flutter_assets")

    def _scan_directory(self, directory: Path, context: str) -> None:
        """Scan a directory for sensitive files"""
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue

            # Skip whitelisted files
            if any(pattern in file_path.name.lower() for pattern in self.WHITELISTED_PATTERNS):
                continue

            # Check by extension
            if file_path.suffix.lower() in self.SENSITIVE_EXTENSIONS:
                self._create_finding(file_path, directory, context, "extension")

            # Check by filename
            elif file_path.name.lower() in {f.lower() for f in self.SENSITIVE_FILENAMES}:
                self._create_finding(file_path, directory, context, "filename")

    def _create_finding(self, file_path: Path, base_dir: Path, context: str, reason: str) -> None:
        """Create a finding for a sensitive file"""
        try:
            relative_path = file_path.relative_to(base_dir.parent if context == "flutter_assets" else base_dir.parent)
            file_size = file_path.stat().st_size

            severity = self._determine_severity(file_path)

            remediation = self._get_remediation(file_path)

            finding = Finding(
                severity=severity,
                title=f"Sensitive File Exposed: {file_path.name}",
                description=(
                    f"File '{file_path.name}' ({file_size} bytes) found at '{relative_path}'. "
                    f"Detected as sensitive {reason}. "
                    f"This file should not be included in production builds."
                ),
                file_path=str(relative_path),
                remediation=remediation,
                owasp="M2: Insecure Data Storage",
                cwe="CWE-312: Cleartext Storage of Sensitive Information"
            )

            self.findings.append(finding)

        except Exception:
            pass

    def _determine_severity(self, file_path: Path) -> Severity:
        """Determine severity based on file type"""
        name_lower = file_path.name.lower()

        # Critical: Keys, keystores, certificates
        if any(ext in name_lower for ext in ['.key', '.pem', '.p12', '.pfx', '.jks', 'keystore']):
            return Severity.CRITICAL

        # Critical: Database files
        if any(ext in name_lower for ext in ['.db', '.sqlite', '.realm']):
            return Severity.CRITICAL

        # High: Config files with likely credentials
        if any(name in name_lower for name in ['secret', 'credential', 'password']):
            return Severity.HIGH

        # Medium: Firebase configs (expected but should be reviewed)
        if 'firebase' in name_lower or 'google-services' in name_lower:
            return Severity.MEDIUM

        # Medium: Other config files
        return Severity.MEDIUM

    def _get_remediation(self, file_path: Path) -> Remediation:
        """Get remediation steps for file type"""
        name_lower = file_path.name.lower()

        if 'firebase' in name_lower or 'google-services' in name_lower:
            return Remediation(
                summary="Restrict Firebase API keys in console",
                root_cause="Firebase configuration files are expected in mobile apps",
                why_wrong=(
                    "Firebase API keys are meant to be public but must be restricted. "
                    "Without restrictions, attackers can abuse your Firebase services."
                ),
                fix_steps=[
                    "1. Go to Firebase Console > Project Settings > API Keys",
                    "2. Restrict Android API key to your package name + SHA-1",
                    "3. Restrict iOS API key to your bundle ID",
                    "4. Enable App Check for additional security",
                    "5. Monitor Firebase usage for anomalies"
                ],
                references=["https://firebase.google.com/docs/projects/api-keys"]
            )

        return Remediation(
            summary=f"Remove {file_path.name} from production build",
            root_cause=f"File was included in assets via pubspec.yaml or build configuration",
            why_wrong=(
                "Sensitive files should never be bundled in production apps. "
                "They can be extracted by anyone and may contain secrets."
            ),
            fix_steps=[
                f"1. Remove {file_path.name} from pubspec.yaml assets",
                "2. Use secure storage (Keychain/KeyStore) for secrets instead",
                "3. Fetch sensitive data from secure backend at runtime",
                "4. Rebuild and verify file is removed"
            ],
            verification=f"Run: fluttersec scan app.apk\nVerify: {file_path.name} not found"
        )
