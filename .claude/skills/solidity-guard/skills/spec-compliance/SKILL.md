---
name: spec-compliance
description: |
  Validates Solidity implementation against specification documents. Extracts behavior
  from docs (README, specs, NatSpec) and verifies code matches documented intent.
  Uses Trail of Bits methodology for divergence detection.
allowed-tools:
  - Read
  - Grep
  - Glob
  - WebFetch
---

# Specification-to-Code Compliance Checker

## 1. Purpose

Detect divergences between documented behavior and actual implementation. Many vulnerabilities arise not from insecure code patterns, but from code that doesn't match the intended design.

## 2. Methodology (Trail of Bits)

### Phase 1: Documentation Discovery
```bash
rg -l "README|SPEC|DESIGN|spec|design" .
rg "/// @" contracts/  # NatSpec comments
rg "@dev|@notice|@param" contracts/
```

### Phase 2: Extract Spec Claims
For each documented behavior:
```markdown
INTENT-001: [Function]
- Claim: "Users can withdraw after 7-day timelock"
- Constraints:
  - C1: Minimum 7 days between request and execution
  - C2: Only original depositor can withdraw
  - C3: Withdrawal amount <= deposited amount
- Source: README.md:45
```

### Phase 3: Map to Code
```markdown
BEHAVIOR-001: withdraw() at contracts/Vault.sol:156
- Observed: Withdrawal has no timelock
- C1: No time check found — DIVERGENCE
- C2: msg.sender check present (line 158) — MATCH
- C3: Balance check present (line 157) — MATCH
```

### Phase 4: Classify Divergences

| Type | Definition | Severity |
|------|------------|----------|
| MISSING | Spec feature not implemented | HIGH |
| EXTRA | Code does more than spec | MEDIUM |
| DIFFERENT | Behavior differs from spec | HIGH |
| AMBIGUOUS | Spec unclear | LOW |
| UNDOCUMENTED | Code behavior not in spec | MEDIUM |

## 3. Anti-Hallucination Rules

1. **Never infer** unspecified behavior
2. **Always cite** exact evidence (file:line or doc section)
3. **Always provide** confidence score
4. **Always classify** ambiguity explicitly
5. **Zero speculation** - only report what's documented vs implemented
