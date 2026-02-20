---
name: solidityguard
description: "Advanced Solidity/EVM smart contract security auditor with 104 vulnerability patterns, multi-tool integration, and professional report generation."
metadata: {"openclaw":{"emoji":"🛡️","homepage":"https://solidityguard.org","os":["darwin","linux","win32"],"requires":{"bins":["python3"],"anyBins":["slither","aderyn"]},"primaryEnv":"SOLIDITYGUARD_PATH","install":{"npm":"solidityguard"}}}
user-invocable: true
---

# SolidityGuard — Smart Contract Security Auditor

Advanced Solidity/EVM smart contract security audit skill with 104 vulnerability patterns covering reentrancy, access control, arithmetic, DeFi, proxy, oracle, transient storage (EIP-1153), account abstraction (ERC-4337), and EIP-7702/Pectra.

## When to Use

Use this skill when:
- The user asks to **audit**, **scan**, or **review** a Solidity smart contract
- The user shares `.sol` or `.vy` files and asks about security
- The user mentions **vulnerability**, **exploit**, **reentrancy**, **access control**, or **security audit**
- The user asks about smart contract best practices or common attack vectors
- The user wants to generate a **security report** for their contracts
- The user wants **fuzz tests** (Foundry/Echidna) generated for their contracts
- The user asks about specific vulnerability patterns (e.g., "check for flash loan attacks")

## Tools

- `solidityguard_scan`: Scans Solidity files for 104 vulnerability patterns using 50+ detectors
- `solidityguard_report`: Generates a professional audit report (Markdown/PDF) from scan findings
- `solidityguard_fuzz`: Generates Foundry invariant tests and Echidna property-based fuzz tests

## Instructions

### Quick Scan

To scan a single contract or directory for vulnerabilities:

```bash
python3 scripts/solidity_guard.py scan <path-to-contracts>
```

This runs the pattern scanner with 50+ detectors covering all 104 vulnerability patterns. Output is JSON with findings including severity, confidence, file:line location, and remediation.

### Full Audit Workflow

For a comprehensive audit, follow this 7-phase workflow:

**Phase 1 — Entry Point Analysis**
Enumerate all external/public functions to map the attack surface:
```bash
# Find all entry points
grep -rn "function.*external\|function.*public" contracts/
```

**Phase 2 — Automated Scan**
Run available security tools, then the pattern scanner:
```bash
# Slither (if installed)
slither . --json slither-results.json 2>/dev/null || true

# Aderyn (if installed)
aderyn -s contracts/ -o aderyn-report.md 2>/dev/null || true

# Pattern scanner (always available)
python3 scripts/solidity_guard.py scan contracts/ --output findings.json
```

**Phase 3 — Finding Verification**
Cross-reference tool outputs. Findings confirmed by 2+ tools get a confidence boost (+10%). Findings confirmed by 3+ tools are capped at 95% confidence.

**Phase 4 — Deduplication**
Remove duplicate findings across tools. Keep the highest-confidence instance.

**Phase 5 — Confidence Filtering**
Filter out findings below 0.70 confidence threshold.

**Phase 6 — Report Generation**
Generate a professional audit report:
```bash
python3 scripts/report_generator.py --input findings.json --output audit-report.md
```

**Phase 7 — Remediation**
For each finding, provide:
- Exact file:line location with vulnerable code snippet
- Step-by-step attack scenario
- Fixed Solidity code

### Vulnerability Categories

The scanner detects 104 patterns organized into these categories:

| Category | Patterns | Examples |
|----------|----------|---------|
| Reentrancy | ETH-001 to ETH-005 | Single, cross-function, cross-contract, read-only, cross-chain |
| Access Control | ETH-006 to ETH-012 | Missing auth, tx.origin, selfdestruct, proxy, centralization |
| Arithmetic | ETH-013 to ETH-017 | Overflow, division-before-multiply, unchecked, rounding, precision |
| External Calls | ETH-018 to ETH-023 | Unchecked return, delegatecall, low-level call, DoS, gas griefing |
| Oracle/Price | ETH-024 to ETH-028 | Manipulation, flash loan, MEV/sandwich, slippage, staleness |
| Storage/State | ETH-029 to ETH-033 | Uninitialized pointer, collision, shadowing, unexpected ether |
| Logic Errors | ETH-034 to ETH-040 | Strict equality, TOD, timestamp, randomness, signature, front-run |
| Token Issues | ETH-041 to ETH-048 | Non-standard ERC20, fee-on-transfer, rebasing, ERC777, zero-addr |
| Proxy/Upgrade | ETH-049 to ETH-054 | Uninitialized impl, storage mismatch, selector clash, upgrade auth |
| DeFi | ETH-055 to ETH-065 | Governance, liquidation, vault inflation, AMM, flash mint, reward |
| Gas/DoS | ETH-066 to ETH-070 | Unbounded loop, block gas limit, revert-in-loop, griefing |
| Miscellaneous | ETH-071 to ETH-080 | Floating pragma, compiler, encodePacked, RTLO, inheritance |
| Transient Storage | ETH-081 to ETH-085 | Slot collision, not cleared, TSTORE reentry bypass, delegatecall |
| EIP-7702/Pectra | ETH-086 to ETH-089 | Broken EOA check, delegation, cross-chain replay, code assumption |
| ERC-4337 AA | ETH-090 to ETH-093 | UserOp collision, paymaster, bundler, validation-execution |
| Modern DeFi | ETH-094 to ETH-097 | Uniswap V4 hooks, hook data, cached state, compiler bugs |
| Input Validation | ETH-098 to ETH-099 | Boundary checks, unsafe ABI decoding |
| Off-Chain | ETH-100 to ETH-101 | Delegation phishing, infrastructure compromise |
| Restaking/L2 | ETH-102 to ETH-104 | Cascading slashing, sequencer dependency, message replay |

### Finding Format

Every finding MUST include:

```
## [SEVERITY] ETH-XXX: Vulnerability Name

**Location**: `contracts/File.sol:123` (functionName)
**Confidence**: 0.XX
**Category**: Category Name

### Description
What the vulnerability is and why it matters.

### Evidence
```solidity
// Vulnerable code from contracts/File.sol:123
<exact code snippet>
```

### Attack Scenario
1. Attacker calls functionA()
2. During callback, attacker re-enters functionB()
3. State is inconsistent, allowing double withdrawal

### Recommendation
```solidity
// Fixed code
<secure implementation>
```
```

### Anti-Hallucination Rules

CRITICAL — All findings MUST include:
- Exact file:line code location (not approximated)
- Vulnerable code snippet (verbatim from source, not generated)
- Specific attack scenario with numbered steps
- Remediation with working Solidity code
- Confidence score >= 0.70

REJECT any finding that:
- Says "this looks vulnerable" without exact pattern match
- Says "probably missing check" without verifying all code paths
- Has confidence below 0.70
- Cannot cite the exact line of vulnerable code

### Tool Integration

The skill works best with these optional tools installed:

| Tool | Install | Purpose |
|------|---------|---------|
| Slither | `pip install slither-analyzer` | Primary static analyzer |
| Aderyn | `curl -L https://raw.githubusercontent.com/Cyfrin/aderyn/dev/cyfrinup/install | bash && cyfrinup` | Fast Rust-based analyzer |
| Mythril | `pip install mythril` | Symbolic execution |
| Foundry | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` | Testing + fuzzing |

### Benchmarks

Validated against real-world CTF challenges:

| Benchmark | Contracts | Detection |
|-----------|-----------|-----------|
| DeFiVulnLabs | 56 contracts, 59 patterns | 100% |
| Paradigm CTF 2021 | 10 static challenges | 100% |
| Paradigm CTF 2022 | 7 static challenges | 100% |
| Paradigm CTF 2023 | 7 static challenges | 100% |

### OWASP Smart Contract Top 10 (2025) Coverage

| Rank | Category | Patterns |
|------|----------|----------|
| #1 | Access Control | ETH-006 to ETH-012, ETH-049 to ETH-054 |
| #2 | Oracle Manipulation | ETH-024 to ETH-028 |
| #3 | Logic Errors | ETH-034 to ETH-040 |
| #4 | Input Validation | ETH-098, ETH-099 |
| #5 | Reentrancy | ETH-001 to ETH-005 |
| #6 | Unchecked Returns | ETH-018 to ETH-023 |
| #7 | MEV / Front-running | ETH-026, ETH-040, ETH-060 |
| #8 | Arithmetic | ETH-013 to ETH-017 |
| #9 | Unsafe Delegatecall | ETH-019, ETH-030 |
| #10 | Denial of Service | ETH-066 to ETH-070 |

## Examples

- "Audit my contracts for reentrancy" → Runs reentrancy-focused scan (ETH-001 to ETH-005)
- "Scan this DeFi protocol" → Full 104-pattern scan with all available tools
- "Check for flash loan vulnerabilities" → Targeted scan for ETH-024, ETH-025, ETH-057
- "Generate a security report" → Professional Markdown audit report
- "Write fuzz tests for this vault" → Foundry invariant tests + Echidna properties
- "Is this proxy upgradeable safely?" → Storage layout + proxy pattern analysis
