# Contributing to FlutterSecAudit

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

Open an issue with:
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Sample APK/IPA (if possible)
- System info (OS, Python version)

### Suggesting Features

Open an issue with:
- Clear use case
- Expected behavior
- Why it would be useful

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add tests for new features
   - Update documentation

4. **Test your changes**
   ```bash
   python3 -m pytest
   python3 -m fluttersec.cli scan test-app.apk
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "feat: add XYZ scanner for ABC vulnerability"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for all public functions
- Keep functions small and focused

## Adding New Scanners

1. Create scanner in `fluttersec/scanners/your_scanner.py`
2. Implement `scan()` method returning `List[Finding]`
3. Add to `__init__.py`
4. Add to CLI in `cli.py`
5. Write tests in `tests/test_your_scanner.py`

Example:

```python
class YourScanner:
    """Scan for XYZ vulnerability"""

    def scan(self, extract_dir: Path) -> List[Finding]:
        findings = []
        # Your scanning logic here
        return findings
```

## Testing

```bash
# Run all tests
python3 -m pytest

# Run specific test
python3 -m pytest tests/test_env_scanner.py

# With coverage
python3 -m pytest --cov=fluttersec
```

## Documentation

- Update README.md for user-facing changes
- Add docstrings for new code
- Create examples for new features

## Questions?

Open a discussion or issue!

Thank you for contributing! 🚀
