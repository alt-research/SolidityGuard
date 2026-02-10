#!/usr/bin/env bash
# SolidityGuard OpenClaw skill installer
# Copies scanner scripts into the skill's scripts/ directory
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="${SKILL_DIR}/../../.claude/skills/solidity-guard/scripts"

echo "SolidityGuard OpenClaw Skill Installer"
echo "======================================="

# Copy core scanner scripts
if [ -d "$SRC_DIR" ]; then
    cp "$SRC_DIR/solidity_guard.py" "$SCRIPT_DIR/" 2>/dev/null || true
    cp "$SRC_DIR/report_generator.py" "$SCRIPT_DIR/" 2>/dev/null || true
    cp "$SRC_DIR/fuzz_generator.py" "$SCRIPT_DIR/" 2>/dev/null || true
    echo "Copied scanner scripts from repository."
else
    echo "Note: Core scanner scripts not found in repo."
    echo "The skill will use standalone mode."
fi

# Check for optional tools
echo ""
echo "Checking optional tools..."
for tool in slither aderyn myth forge echidna medusa halmos certoraRun; do
    if command -v "$tool" &>/dev/null; then
        echo "  [OK] $tool"
    else
        echo "  [--] $tool (not installed)"
    fi
done

echo ""
echo "SolidityGuard skill installed successfully."
echo "Use: solidityguard-scan <path-to-contracts>"
