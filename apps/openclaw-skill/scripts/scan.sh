#!/usr/bin/env bash
# SolidityGuard scanner wrapper for OpenClaw
# Usage: ./scan.sh <path-to-contracts> [--output results.json]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="${SCRIPT_DIR}/solidity_guard.py"

if [ $# -lt 1 ]; then
    echo "Usage: solidityguard-scan <path-to-contracts> [--output results.json]"
    echo ""
    echo "SolidityGuard — AI-powered Solidity security scanner"
    echo "  104 vulnerability patterns (ETH-001 to ETH-104)"
    echo "  50+ pattern detectors"
    echo "  100% detection on DeFiVulnLabs + Paradigm CTF"
    exit 1
fi

TARGET="$1"
shift

python3 "$SCANNER" scan "$TARGET" "$@"
