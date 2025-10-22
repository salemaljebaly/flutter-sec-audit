# FlutterSecAudit

🔒 **Automated security scanner for Flutter apps with attack simulation and detailed remediation**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Features

- ✅ **Comprehensive Scanning** - Detect vulnerabilities in both Android (APK) and iOS (IPA) Flutter apps
- 🎯 **Attack Simulation** - See how long it would take different attackers to compromise your app
- 📚 **Educational Remediation** - Get detailed fix instructions with code examples
- 📊 **Beautiful Reports** - Generate HTML, JSON, and Markdown reports
- 🚀 **CI/CD Ready** - Integrate into your build pipeline
- 🆓 **100% Free & Open Source**

## What It Detects

### Critical Vulnerabilities
- 🔴 Exposed `.env` files
- 🔴 Hardcoded API keys and secrets
- 🔴 Exposed database files
- 🔴 Private keys and certificates

### Configuration Issues
- 🟡 Firebase configuration exposure
- 🟡 Insecure permissions
- 🟡 Missing security features (root detection, SSL pinning)
- 🟡 Weak code obfuscation

### Information Leakage
- 🔵 URLs and API endpoints in binaries
- 🔵 Development paths
- 🔵 Third-party service configurations

## Installation

### From Source (Development)

```bash
# Clone repository
git clone https://github.com/salemaljebaly/flutter-sec-audit.git
cd flutter-sec-audit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 -m fluttersec.cli --help
```

### Using pip (Coming Soon)

```bash
pip install fluttersec
```

## Quick Start

### Activate virtual environment (first time)

```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Scan an APK file

```bash
# Using run script (recommended)
./run.sh scan app-release.apk

# Or directly
python3 -m fluttersec.cli scan app-release.apk
```

### Generate HTML report

```bash
fluttersec scan app-release.apk --format html --output report.html
```

### With attack simulation

```bash
fluttersec scan app-release.apk --attack-sim advanced
```

### Fail CI build on critical issues

```bash
fluttersec scan app-release.apk --fail-on critical --format json --output results.json
```

## Example Output

```
┏━━━━━━━━━━━━━━━━━━━┓
┃ Security Score    ┃
┃                   ┃
┃      62/100       ┃
┃   C (Fair)        ┃
┗━━━━━━━━━━━━━━━━━━━┛

Findings Summary
┌──────────┬───────┬────────┐
│ Severity │ Count │ Status │
├──────────┼───────┼────────┤
│ CRITICAL │   2   │   ✗    │
│ HIGH     │   3   │   ✗    │
│ MEDIUM   │   1   │   ✗    │
│ LOW      │   0   │   ✓    │
└──────────┴───────┴────────┘

Top Priority Issues:
  1. [CRITICAL] .env File Exposed
  2. [CRITICAL] API Keys in Binary
  3. [HIGH] Firebase Configuration Exposed
```

## How It Works

1. **Extract** - Unzip APK/IPA and parse contents
2. **Scan** - Run multiple security scanners:
   - .env file scanner
   - Asset vulnerability scanner
   - String extractor (binary analysis)
3. **Analyze** - Calculate security score and attack surface
4. **Simulate** - Model real-world attack scenarios
5. **Report** - Generate actionable remediation guide

## Attack Simulation

FlutterSecAudit simulates three attacker profiles:

### 🎓 Beginner (Script Kiddie)
- **Time:** 2-5 minutes
- **Tools:** unzip, basic text editors
- **Success Rate:** 60%
- **Can exploit:** Exposed .env files, obvious misconfigurations

### 🔬 Intermediate (Security Researcher)
- **Time:** 10-45 minutes
- **Tools:** APKTool, JADX, Burp Suite
- **Success Rate:** 85%
- **Can exploit:** Most static vulnerabilities, decompile code, analyze network traffic

### 💀 Advanced (Professional Hacker)
- **Time:** 30 minutes - 4 hours
- **Tools:** Frida, IDA Pro, Ghidra, Blutter, custom scripts
- **Success Rate:** 95%
- **Can exploit:** Almost everything including runtime attacks

## Example Findings

### Critical: .env File Exposed

**What we found:**
- File: `assets/flutter_assets/.env`
- Contains: API URLs, Municipality IDs, secrets

**How it happened:**
```yaml
# pubspec.yaml
flutter:
  assets:
    - .env  # ❌ THIS LINE exposes everything
```

**How to fix:**
1. Remove `.env` from `pubspec.yaml`
2. Create `lib/core/config/app_config.dart`:
```dart
class AppConfig {
  static const baseUrl = 'https://api.example.com';
  static const apiPrefix = '/api/v1';
}
```
3. Rebuild: `flutter clean && flutter build apk --release`

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.35.6'

      - name: Build APK
        run: flutter build apk --release

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Clone FlutterSecAudit
        run: git clone https://github.com/salemaljebaly/flutter-sec-audit.git

      - name: Install dependencies
        run: |
          cd flutter-sec-audit
          python3 -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt

      - name: Run security scan
        run: |
          cd flutter-sec-audit
          source venv/bin/activate
          python3 -m fluttersec.cli scan ../build/app/outputs/flutter-apk/app-release.apk \
            --fail-on critical \
            --format json \
            --output ../security-report.json

      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json
```

## Project Structure

```
flutter-sec-audit/
├── fluttersec/
│   ├── extractors/       # APK/IPA extraction
│   ├── scanners/         # Vulnerability scanners
│   ├── analyzers/        # Scoring and attack simulation
│   ├── reporters/        # Report generators
│   └── cli.py            # Command-line interface
├── tests/                # Unit tests
├── examples/             # Example reports
└── docs/                 # Documentation
```

## Development

### Running Tests

```bash
poetry run pytest
```

### Code Formatting

```bash
poetry run black fluttersec/
poetry run ruff check fluttersec/
```

### Adding New Scanners

1. Create scanner in `fluttersec/scanners/`
2. Implement `scan()` method returning `List[Finding]`
3. Add to CLI in `fluttersec/cli.py`

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Submit a pull request

## Roadmap

- [ ] v0.1.0 - Initial release (Android & iOS basics)
- [ ] v0.2.0 - Advanced binary analysis
- [ ] v0.3.0 - Dynamic analysis support
- [ ] v0.4.0 - Vulnerability database with CVE lookup
- [ ] v0.5.0 - Web dashboard (premium)

## License

MIT License - see LICENSE file

## Acknowledgments

Built with inspiration from:
- APKTool
- JADX
- reFlutter
- Blutter
- MobSF

## Support

- 📖 [Documentation](https://github.com/salemaljebaly/flutter-sec-audit/docs)
- 🐛 [Issue Tracker](https://github.com/salemaljebaly/flutter-sec-audit/issues)
- 💬 [Discussions](https://github.com/salemaljebaly/flutter-sec-audit/discussions)

---

**Made with ❤️ for the Flutter community**
