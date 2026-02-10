---
name: solidity-guard:scan-access-control
description: Focused scan for access control vulnerabilities in Solidity contracts
argument-hint: "[path-to-contracts]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Access Control Security Scan

Focused analysis of access control, authorization, and privilege escalation.

## Usage
```
/solidity-guard:scan-access-control ./contracts
```

## Checks
- ETH-006: Missing Access Control (CRITICAL)
- ETH-007: tx.origin Authentication (CRITICAL)
- ETH-008: Unprotected selfdestruct (CRITICAL)
- ETH-009: Default Function Visibility (HIGH)
- ETH-010: Uninitialized Proxy (CRITICAL)
- ETH-011: Missing Modifier on State-changing Function (HIGH)
- ETH-012: Centralization Risk (MEDIUM)
- ETH-049: Uninitialized Implementation (CRITICAL)
- ETH-052: Missing Upgrade Authorization (CRITICAL)

## Quick Detection
```bash
# Find functions without access modifiers
rg -n "function.*external|function.*public" [path]

# Check for tx.origin
rg -n "tx\.origin" [path]

# Find selfdestruct
rg -n "selfdestruct|suicide" [path]

# Check for initializer
rg -n "initializer|initialized" [path]

# Run Slither
slither . --detect unprotected-upgrade,suicidal,tx-origin
```

For each state-changing function, verify proper access control exists.
