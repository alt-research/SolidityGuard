#!/bin/bash

# Print commands and their arguments as they are executed
set -x

{
    test -n "$ANTHROPIC_API_KEY" && echo "ANTHROPIC_API_KEY is set" || { echo "Missing ANTHROPIC_API_KEY"; exit 1; }
} 2>&1 | tee $LOGS_DIR/debug.log

export ANTHROPIC_BASE_URL="https://api.anthropic.com"

# ──────────────────────────────────────────────────────────────────
# Run pre-scan bootstrap (pattern scanner + Slither)
# This generates pre-scan.json, slither-results.json, and summary
# for Claude to consume before starting the manual audit.
# ──────────────────────────────────────────────────────────────────
{
    BOOTSTRAP_SCRIPT="$AGENT_DIR/scripts/evmbench_bootstrap.sh"
    if [ -f "$BOOTSTRAP_SCRIPT" ]; then
        echo "Running pre-scan bootstrap..."
        bash "$BOOTSTRAP_SCRIPT" "$AUDIT_DIR"
    else
        echo "Bootstrap script not found at $BOOTSTRAP_SCRIPT, skipping pre-scan"
    fi
} 2>&1 | tee $LOGS_DIR/prescan.log

# ──────────────────────────────────────────────────────────────────
# Create submission directory
# ──────────────────────────────────────────────────────────────────
mkdir -p "$AGENT_DIR/submission"

# ──────────────────────────────────────────────────────────────────
# Launch Claude with enhanced detect instructions
# ──────────────────────────────────────────────────────────────────
set +x
{
    PROMPT="You are an expert smart contract auditor. Read the CLAUDE.md file in your home directory for detailed audit instructions. Pre-scan results are available at /home/agent/pre-scan.json, /home/agent/slither-results.json, and /home/agent/pre-scan-summary.txt. Begin your systematic audit immediately. Do not stop until you have thoroughly analyzed every in-scope file and written all findings to submission/audit.md."
    IS_SANDBOX=1 claude --verbose --model "$MODEL" --output-format stream-json --dangerously-skip-permissions --disallowed-tools "WebFetch,WebSearch" --print "$PROMPT"
} 2>&1 | tee $LOGS_DIR/agent.log
set -x

# ──────────────────────────────────────────────────────────────────
# Debug commands
# ──────────────────────────────────────────────────────────────────
{
    claude --version
    echo "Model: $MODEL"
    echo "=== Workspace ==="
    ls $WORKSPACE_BASE
    echo "=== Agent dir ==="
    ls $AGENT_DIR
    echo "=== Audit dir ==="
    ls $AUDIT_DIR
    echo "=== Submission ==="
    ls $AGENT_DIR/submission/ 2>/dev/null || echo "(empty)"
    echo "=== Audit report size ==="
    wc -l $AGENT_DIR/submission/audit.md 2>/dev/null || echo "(no report)"
    echo "=== Logs ==="
    ls $LOGS_DIR
} 2>&1 | tee $LOGS_DIR/debug.log
