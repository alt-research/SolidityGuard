---
name: solidity-guard:deep-audit
description: Run a comprehensive security audit using an agent team with specialized teammates working in parallel
argument-hint: "[path-to-contracts]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Write
  - Task
  - TeamCreate
  - TeamDelete
  - TaskCreate
  - TaskUpdate
  - TaskList
  - TaskGet
  - SendMessage
---

# Deep Security Audit with Agent Team

Run a comprehensive security audit using an agent team where specialized teammates analyze different security domains in parallel, challenge each other's findings, and converge on verified vulnerabilities.

## Quick Start

```bash
/solidity-guard:deep-audit ./contracts
```

## Agent Team Architecture

```
┌────────────────────────────────────────────────────────┐
│                    TEAM LEAD                            │
│  Phase 1: Run automated scan (Slither + Aderyn)        │
│  Phase 2: Create tasks, spawn & assign teammates       │
│  Phase 3: Collect results, synthesize findings         │
│  Phase 4: Exploit PoC + dynamic verification           │
│  Phase 5: Fuzz testing (Foundry + Echidna)             │
│  Phase 6: Generate final report                        │
└───────────┬────────────────────────────────────────────┘
            │ spawns & coordinates
    ┌───────┴────────────────────────────────────┐
    │           SHARED TASK LIST                  │
    │  Teammates self-claim unblocked tasks       │
    └───────┬────────────────────────────────────┘
            │
  ┌─────────┼──────────┬──────────┬──────────┐
  ▼         ▼          ▼          ▼          ▼
┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│Reent.│ │Access│ │DeFi/ │ │Logic/│ │Adversary │
│Audit │ │Ctrl  │ │Oracle│ │Math  │ │ Reviewer │
└──────┘ └──────┘ └──────┘ └──────┘ └──────────┘
 ETH-001  ETH-006  ETH-024  ETH-013  Challenges
 ETH-002  ETH-007  ETH-025  ETH-014  all findings
 ETH-003  ETH-010  ETH-026  ETH-018  from other
 ETH-044  ETH-049  ETH-055  ETH-034  teammates
 ETH-081  ETH-086  ETH-094  ETH-097
 ETH-083  ETH-091  ETH-096
```

## Workflow

### Phase 1: Automated Scan (Lead)

The lead runs static analyzers first to establish baseline findings:

```bash
slither [TARGET_PATH] --json /tmp/slither_results.json
aderyn -s [TARGET_PATH] -o /tmp/aderyn_report.md
```

### Phase 2: Create Team and Assign Tasks

Create the agent team:

```
TeamCreate team_name="audit-[contract-name]" description="Security audit of [contract-name]"
```

Create tasks for each security domain:

```
TaskCreate subject="Reentrancy Security Analysis" description="..."
TaskCreate subject="Access Control & Proxy Analysis" description="..."
TaskCreate subject="DeFi/Oracle Security Analysis" description="..."
TaskCreate subject="Logic & Math Analysis" description="..."
TaskCreate subject="Adversarial Finding Review" description="..."  # blocked by the above 4
```

Spawn 5 teammates using the Task tool with `team_name`:

```
Task team_name="audit-[contract]" name="reentrancy-auditor" subagent_type="general-purpose"
     prompt="You are the Reentrancy Security Auditor..."

Task team_name="audit-[contract]" name="access-control-auditor" subagent_type="general-purpose"
     prompt="You are the Access Control & Proxy Auditor..."

Task team_name="audit-[contract]" name="defi-auditor" subagent_type="general-purpose"
     prompt="You are the DeFi/Oracle Security Auditor..."

Task team_name="audit-[contract]" name="logic-auditor" subagent_type="general-purpose"
     prompt="You are the Logic & Math Auditor..."

Task team_name="audit-[contract]" name="adversary" subagent_type="general-purpose"
     mode="plan"
     prompt="You are the Adversarial Reviewer..."
```

### Phase 3: Collect and Synthesize (Lead)

Wait for all teammates to complete their tasks. The lead:
1. Reads each teammate's findings
2. Merges and deduplicates
3. Applies confidence boosting when multiple teammates agree
4. Filters findings below 0.7 confidence

### Phase 4: Exploit PoC & Dynamic Verification (Lead)

For each CRITICAL/HIGH finding, generate and execute exploit PoCs:

1. **Generate Foundry fork test**:
```solidity
function testExploit_Reentrancy() public {
    vm.createSelectFork(ETH_RPC_URL);
    // Setup attacker contract
    // Execute exploit
    // Assert funds drained
}
```

2. **Execute and capture state diffs**:
   - Before-state: account balances, storage slots
   - Execute exploit transaction
   - After-state: verify funds drained or state corrupted
   - Calculate exact loss amount

3. **Promote confirmed findings**: PoC-verified findings get +15% confidence boost

### Phase 5: Fuzz Testing (Lead)

Generate Foundry invariant tests and Echidna properties:

```bash
forge test --match-test "invariant" -vvv
echidna . --contract MyContractTest --config echidna.yaml
```

### Phase 6: Report Generation (Lead)

Generate professional report using the report-generator skill.

Then clean up:

```
# Shut down each teammate
SendMessage type="shutdown_request" recipient="reentrancy-auditor"
SendMessage type="shutdown_request" recipient="access-control-auditor"
SendMessage type="shutdown_request" recipient="defi-auditor"
SendMessage type="shutdown_request" recipient="logic-auditor"
SendMessage type="shutdown_request" recipient="adversary"

# After all shut down
TeamDelete
```

## Teammate Prompt Templates

### Reentrancy Security Auditor

```
You are a Solidity security auditor specializing in reentrancy vulnerabilities.

TARGET: [TARGET_PATH]

Analyze all external calls and state changes in the contracts. For each:

1. Is the Checks-Effects-Interactions (CEI) pattern followed? (ETH-001, ETH-002)
2. Is ReentrancyGuard (or equivalent mutex) used? (ETH-001)
3. Are there cross-function reentrancy paths via shared state? (ETH-002)
4. Are there cross-contract reentrancy paths? (ETH-003)
5. Are there read-only reentrancy risks affecting other protocols? (ETH-004)
6. Are ERC-777 hooks handled safely? (ETH-044)
7. Do callback patterns (ERC-721 onERC721Received, flash loan callbacks) follow CEI? (ETH-064)
8. Are TSTORE-based reentrancy locks using namespaced slots? (ETH-081)
9. Can TSTORE reentrancy guards be bypassed via delegatecall? (ETH-083)
10. Is transient storage safely isolated across delegatecall boundaries? (ETH-084)

For each finding, provide:
- Vulnerability ID and severity (CRITICAL/HIGH/MEDIUM)
- Exact file:line code location
- Verbatim vulnerable code snippet
- Specific attack scenario with steps
- Recommended fix with code

IMPORTANT: Only report findings with confidence >= 0.7. Reject vague claims.
Mark your task as completed when done and send findings to the team lead.
```

### Access Control & Proxy Auditor

```
You are a Solidity security auditor specializing in access control, proxy patterns, EIP-7702, and ERC-4337.

TARGET: [TARGET_PATH]

Analyze all contracts for access control, proxy, and account abstraction vulnerabilities:

1. Missing access control on state-changing functions (ETH-006)
2. tx.origin used for authentication (ETH-007)
3. Unprotected selfdestruct (ETH-008)
4. Default visibility on functions (ETH-009)
5. Uninitialized proxy implementation (ETH-010, ETH-049)
6. Storage layout collision in proxy (ETH-030, ETH-050)
7. Missing upgrade authorization (ETH-052)
8. Function selector clashes (ETH-051)
9. Centralization risks (ETH-012)
10. tx.origin == msg.sender used to detect EOA — broken by EIP-7702 (ETH-086)
11. Malicious EIP-7702 delegation targeting (ETH-087)
12. EIP-7702 authorization replay across chains (ETH-088)
13. extcodesize/isContract used to detect EOA — unreliable post-EIP-7702 (ETH-089)
14. ERC-4337 paymaster without spending limits (ETH-091)
15. ERC-4337 validation phase with side effects (ETH-093)

For each finding, provide:
- Vulnerability ID and severity
- Exact file:line code location
- Verbatim vulnerable code snippet
- Specific attack scenario
- Recommended fix with code

Mark your task as completed when done and send findings to the team lead.
```

### DeFi/Oracle Security Auditor

```
You are a Solidity security auditor specializing in DeFi and oracle security.

TARGET: [TARGET_PATH]

Analyze all DeFi patterns, oracle usage, and modern DeFi hooks:

1. Oracle manipulation vectors — single source, no TWAP (ETH-024)
2. Flash loan attack surfaces (ETH-025)
3. Sandwich/MEV vulnerability (ETH-026)
4. Missing slippage protection (ETH-027)
5. Stale oracle data (ETH-028)
6. Governance manipulation (ETH-055)
7. Liquidation manipulation (ETH-056)
8. Vault share inflation / first depositor attack (ETH-057)
9. Donation attacks (ETH-058)
10. AMM constant product errors (ETH-059)
11. Missing deadline checks (ETH-060)
12. Uniswap V4 hook callback without msg.sender verification (ETH-094)
13. Hook data manipulation by attacker (ETH-095)
14. Cached state desynchronization across external calls (ETH-096)

For each finding, provide:
- Vulnerability ID and severity
- Exact file:line code location
- Verbatim vulnerable code snippet
- Numerical example showing the exploit
- Recommended fix with code

Mark your task as completed when done and send findings to the team lead.
```

### Logic & Math Auditor

```
You are a Solidity security auditor specializing in arithmetic safety and logic vulnerabilities.

TARGET: [TARGET_PATH]

Analyze arithmetic operations and logic patterns:

1. Integer overflow/underflow in unchecked blocks (ETH-013, ETH-015)
2. Division before multiplication (ETH-014)
3. Precision loss in token calculations (ETH-017)
4. Unchecked external call returns (ETH-018)
5. Unsafe low-level calls (ETH-020)
6. Strict equality on balances (ETH-034)
7. Timestamp dependence (ETH-036)
8. Weak randomness (ETH-037)
9. Signature malleability/replay (ETH-038, ETH-039)
10. Fee-on-transfer token handling (ETH-042)
11. Rebasing token handling (ETH-043)
12. Unbounded loops (ETH-066)
13. Known compiler bug in used Solidity version (ETH-097)

For each finding, provide:
- Vulnerability ID and severity
- Exact file:line code location
- Verbatim vulnerable code snippet
- Numerical example showing the bug
- Recommended fix with code

Mark your task as completed when done and send findings to the team lead.
```

### Adversarial Reviewer

```
You are an adversarial security reviewer. Your job is to CHALLENGE findings from the other teammates.

TARGET: [TARGET_PATH]

IMPORTANT: This task is blocked until the 4 audit tasks complete. Once unblocked:

1. Read all findings from the other 4 teammates
2. For EACH finding, attempt to DISPROVE it:
   - Read the actual code at the cited file:line
   - Check if protection exists elsewhere (inherited contracts, libraries, modifiers)
   - Verify the attack scenario is actually feasible on-chain
   - Check for compensating controls that mitigate the risk
3. Classify each finding:
   - TRUE POSITIVE: Confirmed — the exploit works as described
   - FALSE POSITIVE: Disproved — explain why
   - DOWNGRADE: Real issue but lower severity
   - UPGRADE: More severe than claimed

4. For true positives, enhance with:
   - Refined severity (Exploitability x Impact)
   - More detailed exploit scenario
   - Cross-references with other findings

Send your final verified findings list to the team lead.
```

## Confidence Boosting

| Agreement | Confidence |
|-----------|-----------|
| Single teammate | Base (60-85%) |
| Two teammates agree | +10% boost |
| Three+ teammates agree | Cap at 95% |
| Adversary confirms | +5% additional |
| Adversary disproves | Finding rejected |
| Slither/Aderyn agrees | +10% boost |

## Security Scores

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 90-100 | Minimal | Ready for deployment |
| 70-89 | Low | Fix before mainnet |
| 50-69 | Medium | Major fixes required |
| 25-49 | High | Critical remediation |
| 0-24 | Critical | Do not deploy |
