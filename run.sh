#!/bin/bash
# FlutterSecAudit - Convenience run script

# Activate virtual environment
source venv/bin/activate

# Run the CLI with all arguments passed through
python3 -m fluttersec.cli "$@"
