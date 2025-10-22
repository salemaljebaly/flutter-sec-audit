"""
Attack simulation and time-to-compromise calculation
"""
from typing import List, Dict
from ..models import Finding, Severity, AttackProfile


class AttackSimulator:
    """Simulate different attacker profiles and calculate time to compromise"""

    ATTACKER_PROFILES = {
        'beginner': AttackProfile(
            level='Beginner (Script Kiddie)',
            time_minutes=5,
            success_rate=0.60,
            tools=['unzip', 'strings', 'basic text editors'],
            capabilities=[
                'Extract APK/IPA files',
                'View assets and configs',
                'Search for .env files',
                'Read basic text files'
            ]
        ),
        'intermediate': AttackProfile(
            level='Intermediate (Security Researcher)',
            time_minutes=30,
            success_rate=0.85,
            tools=['APKTool', 'JADX', 'Burp Suite', 'strings', 'grep'],
            capabilities=[
                'Everything from beginner',
                'Decompile code',
                'Analyze network traffic',
                'Intercept API calls',
                'Read manifest/plist files',
                'Extract strings from binaries'
            ]
        ),
        'advanced': AttackProfile(
            level='Advanced (Professional Hacker)',
            time_minutes=240,
            success_rate=0.95,
            tools=['Frida', 'IDA Pro', 'Ghidra', 'Hopper', 'reFlutter', 'Blutter', 'Custom scripts'],
            capabilities=[
                'Everything from intermediate',
                'Runtime code injection',
                'Bypass SSL pinning',
                'Bypass root/jailbreak detection',
                'Dump complete Dart code',
                'Dynamic instrumentation',
                'Memory analysis',
                'Patch binaries'
            ]
        )
    }

    def simulate_attack(self, findings: List[Finding]) -> Dict:
        """Simulate attack and determine which attacker can exploit"""
        results = {}

        for level, profile in self.ATTACKER_PROFILES.items():
            exploitable = self._can_exploit(findings, level)
            time_to_compromise = self._calculate_time(findings, level)

            results[level] = {
                'profile': profile,
                'can_exploit': exploitable,
                'time_minutes': time_to_compromise,
                'exploitable_findings': self._get_exploitable_findings(findings, level)
            }

        # Determine most likely attacker
        most_likely = self._determine_likely_attacker(results)

        return {
            'profiles': results,
            'most_likely_attacker': most_likely,
            'overall_time_to_compromise': results[most_likely]['time_minutes'],
            'attack_scenario': self._generate_attack_scenario(findings, most_likely)
        }

    def _can_exploit(self, findings: List[Finding], attacker_level: str) -> bool:
        """Determine if attacker at this level can exploit vulnerabilities"""
        if attacker_level == 'beginner':
            # Can exploit .env files and obvious asset exposures
            return any(
                f.severity == Severity.CRITICAL and
                ('.env' in f.title.lower() or 'exposed' in f.description.lower())
                for f in findings
            )

        elif attacker_level == 'intermediate':
            # Can exploit most static vulnerabilities
            return any(
                f.severity in [Severity.CRITICAL, Severity.HIGH]
                for f in findings
            )

        else:  # advanced
            # Can exploit almost anything
            return len(findings) > 0

    def _calculate_time(self, findings: List[Finding], attacker_level: str) -> int:
        """Calculate time to compromise in minutes"""
        base_time = self.ATTACKER_PROFILES[attacker_level].time_minutes

        # Time varies based on findings
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)

        if attacker_level == 'beginner':
            # Very fast if .env exposed
            if critical > 0:
                return 2  # 2 minutes to unzip and find .env
            return 0  # Can't exploit

        elif attacker_level == 'intermediate':
            # Time based on complexity
            if critical > 0:
                return min(10, 5 + critical * 2)  # 5-10 minutes
            elif high > 0:
                return min(45, 15 + high * 5)  # 15-45 minutes
            return 0

        else:  # advanced
            # Always can compromise, just takes time
            if critical > 0:
                return 30  # 30 minutes
            elif high > 0:
                return 90  # 1.5 hours
            else:
                return 180  # 3 hours for medium/low

    def _get_exploitable_findings(self, findings: List[Finding], attacker_level: str) -> List[str]:
        """Get list of findings this attacker can exploit"""
        exploitable = []

        for finding in findings:
            if attacker_level == 'beginner':
                if finding.severity == Severity.CRITICAL and '.env' in finding.title.lower():
                    exploitable.append(finding.title)

            elif attacker_level == 'intermediate':
                if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                    exploitable.append(finding.title)

            else:  # advanced
                exploitable.append(finding.title)

        return exploitable[:10]  # Limit to top 10

    def _determine_likely_attacker(self, results: Dict) -> str:
        """Determine most likely attacker level based on vulnerabilities"""
        # If beginner can exploit, that's the likely scenario
        if results['beginner']['can_exploit']:
            return 'beginner'

        # If only intermediate+ can exploit
        if results['intermediate']['can_exploit']:
            return 'intermediate'

        # Advanced attacker needed
        return 'advanced'

    def _generate_attack_scenario(self, findings: List[Finding], attacker_level: str) -> List[str]:
        """Generate step-by-step attack scenario"""
        scenario = []
        profile = self.ATTACKER_PROFILES[attacker_level]

        scenario.append(f"**Attacker Profile**: {profile.level}")
        scenario.append(f"**Tools Required**: {', '.join(profile.tools[:3])}")
        scenario.append(f"**Success Rate**: {int(profile.success_rate * 100)}%")
        scenario.append("")
        scenario.append("**Attack Timeline**:")

        if attacker_level == 'beginner':
            critical_env = [f for f in findings if f.severity == Severity.CRITICAL and '.env' in f.title.lower()]
            if critical_env:
                scenario.append("- [00:00:30] Download APK/IPA from device or store")
                scenario.append("- [00:01:00] Extract using unzip command")
                scenario.append("- [00:01:30] Navigate to assets/flutter_assets/")
                scenario.append("- [00:02:00] ✓ Found .env file with API endpoints")
                scenario.append("- [00:02:30] ✓ Extracted all sensitive configuration")
                scenario.append("")
                scenario.append("**Result**: Full API access obtained in < 3 minutes")

        elif attacker_level == 'intermediate':
            scenario.append("- [00:00] Download and extract app")
            scenario.append("- [00:05] Decompile with APKTool/JADX")
            scenario.append("- [00:10] Extract .env and config files")
            scenario.append("- [00:15] Analyze AndroidManifest/Info.plist")
            scenario.append("- [00:20] Extract strings from libapp.so/App binary")
            scenario.append("- [00:25] Map all API endpoints")
            scenario.append("- [00:30] ✓ Complete app infrastructure mapped")
            scenario.append("")
            scenario.append("**Result**: Full understanding of app architecture")

        else:  # advanced
            scenario.append("- [00:00] Extract and decompile app")
            scenario.append("- [00:30] Run Blutter to dump Dart classes")
            scenario.append("- [01:00] Analyze business logic")
            scenario.append("- [01:30] Setup Frida for runtime analysis")
            scenario.append("- [02:00] Bypass SSL pinning")
            scenario.append("- [02:30] Bypass root/jailbreak detection")
            scenario.append("- [03:00] Intercept and modify API calls")
            scenario.append("- [04:00] ✓ Complete compromise achieved")
            scenario.append("")
            scenario.append("**Result**: Full control over app behavior")

        return scenario

    def get_defense_recommendations(self, attacker_level: str) -> List[str]:
        """Get defense recommendations based on threat level"""
        if attacker_level == 'beginner':
            return [
                "1. Remove .env files from production builds immediately",
                "2. Move sensitive data to compile-time constants",
                "3. Verify assets don't contain secrets",
                "4. This will block most unsophisticated attacks"
            ]

        elif attacker_level == 'intermediate':
            return [
                "1. Fix all beginner-level issues",
                "2. Enable code obfuscation (--obfuscate flag)",
                "3. Implement certificate pinning",
                "4. Add root/jailbreak detection",
                "5. Use ProGuard aggressive mode (Android)"
            ]

        else:  # advanced
            return [
                "1. Fix all intermediate-level issues",
                "2. Implement tamper detection",
                "3. Use native code for sensitive logic",
                "4. Add runtime integrity checks",
                "5. Implement Play Integrity API (Android)",
                "6. Monitor for suspicious behavior",
                "7. Consider bug bounty program",
                "Note: Advanced attackers are very difficult to stop completely"
            ]
