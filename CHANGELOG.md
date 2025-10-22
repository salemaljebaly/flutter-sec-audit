# Changelog

All notable changes to FlutterSecAudit will be documented in this file.

## [0.1.0] - 2025-01-22

### Added
- 🎉 Initial MVP release
- APK and IPA extraction support
- Multiple vulnerability scanners:
  - .env file detector
  - Asset vulnerability scanner
  - Binary string analyzer
- Security scoring algorithm (0-100 scale)
- Attack simulation with 3 attacker profiles
- Report generation in 3 formats:
  - HTML (beautiful styled reports)
  - JSON (machine-readable)
  - Markdown (GitHub-friendly)
- Root cause analysis with fix instructions
- Code examples (before/after)
- Professional CLI with Rich output
- Virtual environment setup
- Comprehensive documentation

### Features
- Flutter-specific vulnerability detection
- Time-to-compromise calculation
- OWASP Mobile Top 10 mapping
- CWE classification
- Attack timeline generation
- Priority finding ranking
- CI/CD integration support (--fail-on flag)

### Documentation
- README.md - Main documentation
- QUICKSTART.md - Quick start guide
- INSTALL.md - Installation guide
- CONTRIBUTING.md - Contributor guide
- PROJECT_SUMMARY.md - Project overview
- LICENSE - MIT License

### Technical
- Python 3.10+ support
- 2,118 lines of code
- Clean architecture with separated concerns
- Type hints throughout
- Comprehensive error handling

---

## [Unreleased]

### Planned
- Unit tests with pytest
- PyPI package release
- GitHub Actions CI/CD
- More vulnerability scanners
- Advanced binary analysis
- Certificate pinning detection
- Dependency vulnerability checking

---

Format: [version] - YYYY-MM-DD
