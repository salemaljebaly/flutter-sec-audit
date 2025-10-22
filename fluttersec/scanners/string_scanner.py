"""
Scanner for sensitive strings in native libraries
"""
from pathlib import Path
from typing import List, Set, Dict
import re
from ..models import Finding, Severity, Remediation


class StringScanner:
    """Scan native libraries for sensitive strings"""

    # Patterns to detect in strings
    PATTERNS = {
        'api_key': re.compile(r'api[_-]?key|apikey', re.IGNORECASE),
        'secret': re.compile(r'secret|password|passwd|pwd', re.IGNORECASE),
        'token': re.compile(r'token|auth[_-]?token', re.IGNORECASE),
        'url': re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'ip': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'private_key': re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    }

    # Common false positives to ignore
    WHITELIST_DOMAINS = {
        'schemas.android.com',
        'xmlpull.org',
        'w3.org',
        'apache.org',
        'eclipse.org',
        'tile.openstreetmap.org',
    }

    def __init__(self):
        self.findings: List[Finding] = []
        self.found_strings: Dict[str, Set[str]] = {}

    def scan(self, extract_dir: Path, platform: str = "android") -> List[Finding]:
        """Scan native libraries for sensitive strings"""
        self.findings = []
        self.found_strings = {}

        if platform.lower() == "android":
            self._scan_android(extract_dir)
        elif platform.lower() == "ios":
            self._scan_ios(extract_dir)

        return self.findings

    def _scan_android(self, extract_dir: Path) -> None:
        """Scan Android native libraries"""
        # Find libapp.so (contains Dart code)
        lib_dirs = extract_dir.glob("lib/*/libapp.so")

        for libapp in lib_dirs:
            if libapp.exists():
                strings = self._extract_strings(libapp)
                self._analyze_strings(strings, libapp, "libapp.so")
                break  # Only scan one architecture

    def _scan_ios(self, extract_dir: Path) -> None:
        """Scan iOS app binary"""
        # Find App binary
        payload = extract_dir / "Payload"
        if payload.exists():
            app_dirs = list(payload.glob("*.app"))
            if app_dirs:
                app_binary = app_dirs[0] / "Frameworks" / "App.framework" / "App"
                if app_binary.exists():
                    strings = self._extract_strings(app_binary)
                    self._analyze_strings(strings, app_binary, "App")

    def _extract_strings(self, binary_path: Path, min_length: int = 8) -> List[str]:
        """Extract printable strings from binary"""
        strings = []
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            current_string = []
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings.append(''.join(current_string))
                    current_string = []

            if len(current_string) >= min_length:
                strings.append(''.join(current_string))

        except Exception:
            pass

        return strings

    def _analyze_strings(self, strings: List[str], binary_path: Path, binary_name: str) -> None:
        """Analyze extracted strings for sensitive data"""
        for pattern_name, pattern in self.PATTERNS.items():
            matches = set()

            for string in strings:
                if pattern.search(string):
                    # Skip whitelisted domains
                    if pattern_name == 'url' and any(domain in string for domain in self.WHITELIST_DOMAINS):
                        continue

                    matches.add(string)

            if matches:
                self.found_strings[pattern_name] = matches
                self._create_finding(pattern_name, matches, binary_name)

    def _create_finding(self, pattern_name: str, matches: Set[str], binary_name: str) -> None:
        """Create finding for detected pattern"""
        severity = self._determine_severity(pattern_name)

        # Limit displayed matches
        sample_matches = list(matches)[:5]
        match_preview = '\n'.join(f"  - {m}" for m in sample_matches)
        if len(matches) > 5:
            match_preview += f"\n  ... and {len(matches) - 5} more"

        title_map = {
            'api_key': "API Keys in Binary",
            'secret': "Secrets in Binary",
            'token': "Tokens in Binary",
            'url': "URLs Exposed in Binary",
            'email': "Email Addresses in Binary",
            'ip': "IP Addresses in Binary",
            'aws_key': "AWS Access Keys in Binary",
            'private_key': "Private Keys in Binary",
        }

        remediation = Remediation(
            summary=f"Obfuscate or encrypt {pattern_name} in code",
            root_cause="Sensitive strings are hardcoded in Dart/Flutter code",
            why_wrong=(
                "Strings in compiled binaries can be extracted using simple tools. "
                "Hardcoded secrets, URLs, and keys are visible to attackers."
            ),
            fix_steps=[
                "1. Move sensitive values to secure backend",
                "2. Use runtime key derivation instead of hardcoding",
                "3. Enable Dart code obfuscation: flutter build --obfuscate",
                "4. Consider string encryption for critical values",
                "5. Use ProGuard aggressive mode (Android)"
            ],
            code_before="""// ❌ BAD: Hardcoded in code
const apiKey = 'sk_live_123456789';
const apiUrl = 'https://api.example.com';""",
            code_after="""// ✅ GOOD: Fetch from secure backend
class SecureConfig {
  static Future<String> getApiKey() async {
    // Fetch from your secure backend
    final response = await api.getConfig();
    return decrypt(response.encryptedKey);
  }
}""",
            verification="Run: strings libapp.so | grep -i 'api\\|secret'\nExpect: Obfuscated/encrypted values"
        )

        finding = Finding(
            severity=severity,
            title=title_map.get(pattern_name, f"{pattern_name} Found"),
            description=(
                f"Found {len(matches)} instances of {pattern_name} in {binary_name}:\n\n"
                f"{match_preview}"
            ),
            file_path=binary_name,
            remediation=remediation,
            owasp="M9: Reverse Engineering",
            cwe="CWE-798: Use of Hard-coded Credentials"
        )

        self.findings.append(finding)

    def _determine_severity(self, pattern_name: str) -> Severity:
        """Determine severity based on pattern type"""
        critical_patterns = {'aws_key', 'private_key', 'secret', 'api_key', 'token'}
        high_patterns = {'url'}
        medium_patterns = {'email', 'ip'}

        if pattern_name in critical_patterns:
            return Severity.CRITICAL
        elif pattern_name in high_patterns:
            return Severity.HIGH
        elif pattern_name in medium_patterns:
            return Severity.MEDIUM
        else:
            return Severity.LOW
