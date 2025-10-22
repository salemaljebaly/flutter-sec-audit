# Installation Guide

Complete guide for installing and setting up FlutterSecAudit.

## Requirements

- **Python**: 3.10 or higher
- **OS**: macOS, Linux, or Windows
- **Storage**: ~50 MB for dependencies

## Installation Methods

### Method 1: Virtual Environment (Recommended)

Best for development and testing.

```bash
# 1. Clone repository
git clone https://github.com/salemaljebaly/flutter-sec-audit.git
cd flutter-sec-audit

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate          # macOS/Linux
# OR
venv\Scripts\activate              # Windows

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python3 -m fluttersec.cli --version
```

**Usage:**
```bash
# Always activate venv first
source venv/bin/activate

# Then run commands
python3 -m fluttersec.cli scan app.apk

# Or use convenience script
./run.sh scan app.apk
```

### Method 2: System-wide Install (Coming Soon)

```bash
pip install fluttersec
fluttersec scan app.apk
```

### Method 3: Docker (Coming Soon)

```bash
docker run -v $(pwd):/app fluttersec scan /app/app-release.apk
```

## Development Setup

For contributors and developers:

```bash
# 1. Clone and setup
git clone https://github.com/salemaljebaly/flutter-sec-audit.git
cd flutter-sec-audit
python3 -m venv venv
source venv/bin/activate

# 2. Install dev dependencies
pip install -r requirements-dev.txt

# 3. Run tests
pytest

# 4. Code formatting
black fluttersec/
ruff check fluttersec/

# 5. Type checking
mypy fluttersec/
```

## Verification

After installation, verify everything works:

```bash
# Check version
python3 -m fluttersec.cli --version

# Check help
python3 -m fluttersec.cli --help

# Test with sample APK
python3 -m fluttersec.cli scan path/to/test.apk
```

## Troubleshooting

### Issue: `python3: command not found`

**Solution:**
```bash
# Try python instead of python3
python -m fluttersec.cli --version
```

### Issue: `No module named 'click'`

**Solution:**
```bash
# Make sure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: Permission denied on run.sh

**Solution:**
```bash
chmod +x run.sh
```

### Issue: Old Python version

**Solution:**
```bash
# Check version
python3 --version

# Need Python 3.10+
# Install from: https://www.python.org/downloads/
```

## Uninstallation

### If using virtual environment:
```bash
# Just delete the directory
cd ..
rm -rf flutter-sec-audit
```

### If installed system-wide:
```bash
pip uninstall fluttersec
```

## Next Steps

- Read [QUICKSTART.md](QUICKSTART.md) for usage examples
- Read [README.md](README.md) for full documentation
- Join discussions on GitHub

## Support

Having issues?
- Check [Issues](https://github.com/salemaljebaly/flutter-sec-audit/issues)
- Ask in [Discussions](https://github.com/salemaljebaly/flutter-sec-audit/discussions)
