#!/bin/bash
# EVMBench Pre-scan Bootstrap Script
# Runs BEFORE Claude agent starts in EVMBench Docker container.
# 1. Copies SolidityGuard scanner into the container
# 2. Runs pattern scan on the audit codebase
# 3. Runs Slither if available
# 4. Generates a pre-scan summary for Claude to consume
#
# Usage: bash evmbench_bootstrap.sh [AUDIT_DIR]
# Exit 0 always — must not block the agent if anything fails.

set -o pipefail

AUDIT_DIR="${1:-${AUDIT_DIR:-/home/agent/audit}}"
AGENT_DIR="${AGENT_DIR:-/home/agent}"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PRESCAN_JSON="$AGENT_DIR/pre-scan.json"
SLITHER_JSON="$AGENT_DIR/slither-results.json"
SUMMARY_FILE="$AGENT_DIR/pre-scan-summary.txt"

echo "=== EVMBench Pre-scan Bootstrap ==="
echo "Audit directory: $AUDIT_DIR"
echo "Agent directory: $AGENT_DIR"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ──────────────────────────────────────────────────────────────────
# Step 1: Copy SolidityGuard scanner into the container
# ──────────────────────────────────────────────────────────────────
SCANNER_SRC="$SCRIPTS_DIR/solidity_guard.py"
SCANNER_DST="$AGENT_DIR/scripts/solidity_guard.py"

mkdir -p "$AGENT_DIR/scripts"

if [ -f "$SCANNER_SRC" ]; then
    cp "$SCANNER_SRC" "$SCANNER_DST"
    echo "[OK] Copied solidity_guard.py to $SCANNER_DST"
else
    # Try to find it relative to common locations
    for candidate in \
        "/home/coder/github/solidity-audit/.claude/skills/solidity-guard/scripts/solidity_guard.py" \
        "$AGENT_DIR/solidity_guard.py" \
        "./solidity_guard.py"; do
        if [ -f "$candidate" ]; then
            cp "$candidate" "$SCANNER_DST"
            echo "[OK] Copied solidity_guard.py from $candidate"
            break
        fi
    done
fi

# ──────────────────────────────────────────────────────────────────
# Step 2: Enumerate in-scope Solidity files
# ──────────────────────────────────────────────────────────────────
SOL_FILES=$(find "$AUDIT_DIR" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/forge-std/*" -not -path "*/@openzeppelin/*" -not -path "*/test/*" -not -path "*/tests/*" -not -path "*/mock/*" -not -path "*/mocks/*" 2>/dev/null)
SOL_COUNT=$(echo "$SOL_FILES" | grep -c '\.sol$' 2>/dev/null || echo "0")
echo "[INFO] Found $SOL_COUNT in-scope Solidity files"

# Save file list for Claude
echo "$SOL_FILES" > "$AGENT_DIR/in-scope-files.txt"

# ──────────────────────────────────────────────────────────────────
# Step 3: Run SolidityGuard pattern scanner
# ──────────────────────────────────────────────────────────────────
if [ -f "$SCANNER_DST" ]; then
    echo "[RUN] Running SolidityGuard pattern scanner..."
    python3 "$SCANNER_DST" "$AUDIT_DIR" --output json -f "$PRESCAN_JSON" --tools patterns 2>/dev/null || true

    if [ -f "$PRESCAN_JSON" ] && [ -s "$PRESCAN_JSON" ]; then
        FINDING_COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('$PRESCAN_JSON'))
    findings = data.get('findings', [])
    print(len(findings))
except:
    print('0')
" 2>/dev/null || echo "0")
        echo "[OK] Pattern scan complete: $FINDING_COUNT findings"
    else
        echo "[WARN] Pattern scan produced no output"
        echo '{"findings": [], "summary": {"total": 0}, "error": "scan produced no output"}' > "$PRESCAN_JSON"
    fi
else
    echo "[WARN] solidity_guard.py not found, skipping pattern scan"
    echo '{"findings": [], "summary": {"total": 0}, "error": "scanner not available"}' > "$PRESCAN_JSON"
fi

# ──────────────────────────────────────────────────────────────────
# Step 4: Run Slither (graceful if not installed)
# ──────────────────────────────────────────────────────────────────
if command -v slither &>/dev/null; then
    echo "[RUN] Running Slither..."
    # Try with JSON output, timeout after 300s
    timeout 300 slither "$AUDIT_DIR" --json "$SLITHER_JSON" 2>/dev/null || true

    if [ -f "$SLITHER_JSON" ] && [ -s "$SLITHER_JSON" ]; then
        SLITHER_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$SLITHER_JSON'))
    detectors = data.get('results', {}).get('detectors', [])
    print(len(detectors))
except:
    print('0')
" 2>/dev/null || echo "0")
        echo "[OK] Slither complete: $SLITHER_COUNT detectors fired"
    else
        echo "[WARN] Slither produced no JSON output"
        echo '{"results": {"detectors": []}, "error": "slither produced no output"}' > "$SLITHER_JSON"
    fi
else
    echo "[INFO] Slither not installed, skipping (pip install slither-analyzer)"
    echo '{"results": {"detectors": []}, "error": "slither not installed"}' > "$SLITHER_JSON"
fi

# ──────────────────────────────────────────────────────────────────
# Step 5: Generate pre-scan summary
# ──────────────────────────────────────────────────────────────────
python3 - "$PRESCAN_JSON" "$SLITHER_JSON" "$SOL_COUNT" <<'PYEOF' > "$SUMMARY_FILE" 2>/dev/null || true
import json, sys
from collections import Counter

prescan_path = sys.argv[1]
slither_path = sys.argv[2]
sol_count = sys.argv[3]

summary_lines = []
summary_lines.append(f"=== PRE-SCAN SUMMARY ===")
summary_lines.append(f"In-scope Solidity files: {sol_count}")

# Parse pattern scan results
try:
    with open(prescan_path) as f:
        prescan = json.load(f)
    findings = prescan.get("findings", [])
    summary_lines.append(f"\n--- Pattern Scanner ---")
    summary_lines.append(f"Total findings: {len(findings)}")

    if findings:
        sev_counts = Counter(f.get("severity", "UNKNOWN") for f in findings)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            if sev_counts.get(sev, 0) > 0:
                summary_lines.append(f"  {sev}: {sev_counts[sev]}")

        cat_counts = Counter(f.get("category", "unknown") for f in findings)
        summary_lines.append(f"\nCategories found:")
        for cat, count in cat_counts.most_common(20):
            summary_lines.append(f"  {cat}: {count}")

        summary_lines.append(f"\nFiles with findings:")
        file_counts = Counter(f.get("file", "unknown") for f in findings)
        for fpath, count in file_counts.most_common(30):
            summary_lines.append(f"  {fpath}: {count} findings")
except Exception as e:
    summary_lines.append(f"Pattern scan: error reading results ({e})")

# Parse Slither results
try:
    with open(slither_path) as f:
        slither = json.load(f)
    detectors = slither.get("results", {}).get("detectors", [])
    summary_lines.append(f"\n--- Slither ---")
    summary_lines.append(f"Total detectors fired: {len(detectors)}")

    if detectors:
        impact_counts = Counter(d.get("impact", "Unknown") for d in detectors)
        for impact in ["High", "Medium", "Low", "Informational"]:
            if impact_counts.get(impact, 0) > 0:
                summary_lines.append(f"  {impact}: {impact_counts[impact]}")

        check_counts = Counter(d.get("check", "unknown") for d in detectors)
        summary_lines.append(f"\nDetector types:")
        for check, count in check_counts.most_common(20):
            summary_lines.append(f"  {check}: {count}")
except Exception as e:
    summary_lines.append(f"Slither: error reading results ({e})")

print("\n".join(summary_lines))
PYEOF

if [ -f "$SUMMARY_FILE" ] && [ -s "$SUMMARY_FILE" ]; then
    echo ""
    echo "--- Pre-scan Summary ---"
    cat "$SUMMARY_FILE"
    echo ""
else
    echo "[WARN] Failed to generate summary"
fi

echo "=== Pre-scan Bootstrap Complete ==="
exit 0
