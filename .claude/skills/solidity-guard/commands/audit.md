---
name: solidity-guard:audit
description: Complete security audit of Solidity contracts with 104 vulnerability patterns
argument-hint: "[path-to-contracts]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Write
  - Task
---

# Full Solidity Smart Contract Security Audit

Run a comprehensive security audit on Solidity contracts using Slither, Aderyn, Mythril, Medusa, Halmos, and manual analysis with 104 vulnerability patterns.

## Quick Start
```bash
# Run Slither
slither . --json slither-results.json

# Run Aderyn
aderyn -s contracts/ -o aderyn-report.md

# Mythril (single contract)
myth analyze contracts/MyContract.sol -o json > mythril-results.json
```

## Manual Audit Workflow

1. **Framework Detection**
   - Identify Hardhat, Foundry, or Truffle
   - Check Solidity compiler version
   - Locate all contract entry points

2. **Entry Point Mapping**
   - Find all `external` and `public` functions
   - Map contract inheritance hierarchy
   - Identify admin/privileged functions
   - Map token approvals and transfers

3. **Vulnerability Scanning (97 patterns)**

   **Critical (CRITICAL)**
   - ETH-001: Single-function Reentrancy
   - ETH-006: Missing Access Control
   - ETH-007: tx.origin Authentication
   - ETH-008: Unprotected selfdestruct
   - ETH-019: Delegatecall to Untrusted Callee
   - ETH-024: Oracle Manipulation
   - ETH-025: Flash Loan Attack Vector
   - ETH-030: Storage Collision (Proxy)
   - ETH-039: Signature Replay
   - ETH-044: ERC-777 Reentrancy Hook
   - ETH-049: Uninitialized Implementation
   - ETH-052: Missing Upgrade Authorization
   - ETH-057: Vault Share Inflation
   - ETH-081: Transient Storage Slot Collision (EIP-1153)
   - ETH-083: TSTORE Reentrancy Bypass
   - ETH-086: Broken tx.origin==msg.sender (EIP-7702)
   - ETH-088: EIP-7702 Cross-Chain Auth Replay
   - ETH-091: Paymaster Exploitation (ERC-4337)
   - ETH-093: Validation-Execution Confusion (ERC-4337)
   - ETH-094: Uniswap V4 Hook Auth Bypass

   **High**
   - ETH-002: Cross-function Reentrancy
   - ETH-003: Cross-contract Reentrancy
   - ETH-009: Default Visibility
   - ETH-013: Integer Overflow/Underflow
   - ETH-018: Unchecked External Call
   - ETH-026: Sandwich Attack / MEV
   - ETH-034: Strict Equality on Balance
   - ETH-037: Weak Randomness
   - ETH-041: ERC-20 Non-standard Returns
   - ETH-066: Unbounded Loop
   - ETH-082: Transient Storage Not Cleared
   - ETH-084: Transient Storage Delegatecall Exposure
   - ETH-087: Malicious EIP-7702 Delegation
   - ETH-089: EOA Code Assumption Failure
   - ETH-090: UserOp Hash Collision (ERC-4337)
   - ETH-092: Bundler Manipulation
   - ETH-095: Hook Data Manipulation
   - ETH-096: Cached State Desynchronization
   - ETH-097: Known Compiler Bug in Used Version

4. **Evidence Collection**
   - Exact file:line for each finding
   - Code snippets as evidence
   - Confidence scores (Slither: 80%, Mythril: 85%, Multi-tool: 95%)

5. **Report Generation**
   After scanning is complete, ALWAYS generate a professional report:
   ```bash
   # Save findings to JSON first (the CLI audit -o flag does this)
   # Then generate the report:
   python3 .claude/skills/solidity-guard/scripts/report_generator.py /tmp/audit_results.json --output audit-report.md --project "[PROJECT_NAME]"
   ```

   If the scan was done via CLI (`solidityguard audit ... -o results.json`), generate the report from results.json:
   ```bash
   python3 .claude/skills/solidity-guard/scripts/report_generator.py results.json -o audit-report.md
   ```

   The report includes:
   - Executive Summary with security score (0-100)
   - Severity distribution
   - Detailed findings with file:line, code snippets, attack scenarios
   - Remediation recommendations with fixed code
   - Methodology and tool versions

   **IMPORTANT**: Always output the report file path so the user can access it. If no JSON file exists, construct one from the findings collected during the audit phases and then generate the report.

## Deep Analysis with Agent Teams

### Phase 1: Automated Scan
```bash
slither . --json slither-results.json
aderyn -s contracts/ -o aderyn-report.md
```

### Phase 2: Finding Verification (Reduce False Positives)
```bash
# Cross-reference Slither + Aderyn findings
# Verify each critical finding manually
Task subagent_type=Explore prompt="Verify the reentrancy finding at contracts/Vault.sol:45. Check if ReentrancyGuard is used, if CEI pattern is followed, and determine if this is a true positive."
```

### Phase 3: Parallel Deep Analysis
```
# Reentrancy Agent
Task subagent_type=Explore prompt="Analyze all external calls and state changes. For each: 1) Is CEI pattern followed? 2) Is ReentrancyGuard used? 3) Are there cross-function reentrancy paths? Report with file:line."

# Access Control Agent
Task subagent_type=Explore prompt="Analyze all state-changing functions. Check for: 1) Missing onlyOwner/access control 2) tx.origin usage 3) Centralization risks. Report with file:line."

# DeFi/Oracle Agent
Task subagent_type=Explore prompt="Analyze all price feeds and oracle usage. Check for: 1) Single oracle source 2) Missing staleness checks 3) Flash loan vectors 4) Slippage protection. Report with file:line."
```

### Phase 4: Exploit Scenario Generation
```
Task subagent_type=Plan prompt="For the reentrancy finding at Vault.sol:45, create a detailed exploit:
1. Attacker deploys malicious contract with receive() callback
2. Attacker calls withdraw() which sends ETH before updating balance
3. receive() callback re-enters withdraw()
4. Estimate impact (fund loss amount)"
```

### Phase 5: Remediation Code Generation
```
Task subagent_type=general-purpose prompt="Generate the fixed code for the reentrancy at Vault.sol:45. Apply CEI pattern and add ReentrancyGuard."
```

## CI Integration

Add to `.github/workflows/audit.yml`:
```yaml
- name: Run Slither
  run: slither . --json slither-results.json

- name: Fail on Critical
  run: |
    CRITICAL=$(python3 -c "
    import json
    with open('slither-results.json') as f:
        data = json.load(f)
    high = [d for d in data.get('results',{}).get('detectors',[]) if d['impact']=='High']
    print(len(high))
    ")
    if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
```

## Key Detection Patterns

| Pattern | Detection Method | Confidence |
|---------|-----------------|------------|
| Reentrancy | Slither + manual CEI check | 85% |
| Missing access control | Slither + Aderyn | 80% |
| Unchecked return | Slither detector | 80% |
| Oracle manipulation | Manual + context | 75% |
| Storage collision | Slither + manual proxy review | 85% |

## Resources

- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Trail of Bits Building Secure Contracts](https://secure-contracts.com/)
- [Cyfrin Audit Methodology](https://www.cyfrin.io/blog/10-steps-to-systematically-approach-a-smart-contract-audit)
