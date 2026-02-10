#!/usr/bin/env bash
# SolidityGuard report generator wrapper for OpenClaw
# Usage: ./report.sh --input findings.json --output audit-report.md
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR="${SCRIPT_DIR}/report_generator.py"

if [ $# -lt 1 ]; then
    echo "Usage: solidityguard-report --input findings.json --output audit-report.md"
    echo ""
    echo "SolidityGuard — Professional audit report generator"
    echo "  OpenZeppelin/Trail of Bits style reports"
    echo "  Markdown + PDF output"
    echo "  Severity scoring and risk assessment"
    exit 1
fi

python3 "$GENERATOR" "$@"
