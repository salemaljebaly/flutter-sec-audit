# FlutterSecAudit - Quick Start Guide

Get started with FlutterSecAudit in under 5 minutes!

## Installation

### Option 1: From Source (Recommended for Development)

```bash
# Clone repository
git clone https://github.com/salemaljebaly/flutter-sec-audit.git
cd flutter-sec-audit

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -m fluttersec.cli --help
```

### Option 2: Using pip (Coming Soon)

```bash
pip3 install fluttersec
fluttersec --help
```

## Your First Scan

### 1. Build Your Flutter App

```bash
cd your-flutter-app
flutter build apk --release
```

The APK will be at: `build/app/outputs/flutter-apk/app-release.apk`

### 2. Run Basic Scan

```bash
cd flutter-sec-audit

# Activate virtual environment
source venv/bin/activate

# Run scan (option 1 - using convenience script)
./run.sh scan ~/path/to/app-release.apk

# Run scan (option 2 - direct)
python3 -m fluttersec.cli scan ~/path/to/app-release.apk
```

**Output:**
```
╭────────────────────────────────────╮
│ FlutterSecAudit - Security Scanner │
╰────────────── v0.1.0 ──────────────╯

→ Platform: Android
→ File: app-release.apk

Security Score: 62/100 - C (Fair)

Findings Summary:
  CRITICAL: 2
  HIGH: 3
  MEDIUM: 1
```

### 3. Generate HTML Report

```bash
python3 -m fluttersec.cli scan app-release.apk \
  --format html \
  --output security-report.html
```

Open `security-report.html` in your browser to see:
- Beautiful visual report
- All findings with details
- Fix instructions with code examples
- OWASP mappings

### 4. With Attack Simulation

```bash
python3 -m fluttersec.cli scan app-release.apk \
  --attack-sim intermediate
```

See how long it would take different attackers to compromise your app:
- **Beginner**: 2-5 minutes
- **Intermediate**: 10-45 minutes
- **Advanced**: 30 minutes - 4 hours

### 5. For CI/CD (Fail on Critical Issues)

```bash
python3 -m fluttersec.cli scan app-release.apk \
  --fail-on critical \
  --format json \
  --output results.json
```

Exit code 1 if critical issues found (perfect for CI pipelines).

## Understanding Results

### Security Score
- **90-100 (A)**: Excellent - Well protected
- **75-89 (B)**: Good - Minor improvements needed
- **60-74 (C)**: Fair - Several issues to address
- **40-59 (D)**: Poor - Significant vulnerabilities
- **0-39 (F)**: Critical - Immediate action required

### Severity Levels

**🔴 CRITICAL** - Fix immediately:
- Exposed .env files
- Hardcoded secrets
- API keys in code
- Private keys

**🟠 HIGH** - Fix within 1 week:
- Missing security features
- Weak obfuscation
- Exposed configuration

**🟡 MEDIUM** - Fix next sprint:
- Firebase config without restrictions
- Development paths leaked
- Suboptimal configurations

**🔵 LOW** - Consider fixing:
- Minor information disclosure
- Optimization opportunities

## Common Issues & Fixes

### Issue: .env File Exposed

**Found:**
```yaml
# pubspec.yaml
flutter:
  assets:
    - .env  # ❌ EXPOSED
```

**Fix:**
```yaml
# pubspec.yaml
flutter:
  assets:
    # - .env  # ✅ REMOVED

# lib/core/config/app_config.dart
class AppConfig {
  static const baseUrl = 'https://api.example.com';
}
```

### Issue: Low Security Score

1. Remove `.env` files
2. Enable obfuscation: `flutter build apk --release --obfuscate --split-debug-info=build/debug`
3. Add ProGuard rules (Android)
4. Implement certificate pinning
5. Add root/jailbreak detection

## Next Steps

- Read full [README.md](README.md)
- Check [CONTRIBUTING.md](CONTRIBUTING.md) to help improve the tool
- Star the repo if you find it useful!
- Report issues or request features

## Support

- 📖 Documentation: [docs/](docs/)
- 🐛 Issues: [GitHub Issues](https://github.com/salemaljebaly/flutter-sec-audit/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/salemaljebaly/flutter-sec-audit/discussions)

---

Happy securing! 🔒
