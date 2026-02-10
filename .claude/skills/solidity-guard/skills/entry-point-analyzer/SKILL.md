---
name: entry-point-analyzer
description: |
  Analyzes Solidity contract entry points to map attack surface. Identifies all
  external/public functions, categorizes by privilege level, maps access control,
  and detects authorization patterns. Use as first step in any audit.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Entry Point Analyzer

## 1. Purpose

Map the complete attack surface of Solidity contracts by analyzing all entry points. This is the essential first step in any security audit.

## 2. When to Use

- Start of any audit (ALWAYS use first)
- Understanding unfamiliar codebase
- Mapping privilege boundaries
- Creating audit scope document

## 3. Analysis Workflow

### Step 1: Detect Framework
```bash
# Check for Foundry
ls foundry.toml

# Check for Hardhat
ls hardhat.config.js hardhat.config.ts

# Check Solidity version
rg "pragma solidity" contracts/
```

### Step 2: Extract All Entry Points
```bash
# Find all external/public functions
rg "function.*external|function.*public" contracts/ --type sol

# Find all state-changing functions
rg "function.*(external|public)" contracts/ -A 5

# Find constructors and initializers
rg "constructor|initialize" contracts/
```

### Step 3: Categorize Functions

| Category | Examples | Risk Level |
|----------|----------|------------|
| **Admin** | initialize, setAdmin, pause, upgrade | CRITICAL |
| **Financial** | deposit, withdraw, transfer, swap, borrow | CRITICAL |
| **State Mutation** | update, set, modify, approve | HIGH |
| **View/Pure** | get, view, balanceOf, totalSupply | LOW |
| **User Action** | claim, stake, vote, mint | MEDIUM |

### Step 4: Map Access Control

For each function, extract:
```markdown
## Function: withdraw(uint256 amount)
- **Visibility**: external
- **Modifiers**: onlyOwner, nonReentrant
- **State Changes**: balances mapping, totalDeposits
- **External Calls**: token.transfer()
- **Events**: Withdrawal(sender, amount)
- **Risk Level**: CRITICAL
```

### Step 5: Identify Privilege Boundaries
```
┌─────────────────────────────────────────────┐
│                 OWNER ONLY                   │
│  pause(), unpause(), setFee(), upgrade()    │
├─────────────────────────────────────────────┤
│              AUTHORIZED ROLES                │
│  withdraw(), liquidate(), harvest()         │
├─────────────────────────────────────────────┤
│                 ANY USER                     │
│  deposit(), swap(), getPrice()              │
└─────────────────────────────────────────────┘
```

## 4. Output Format

```markdown
# Entry Point Analysis: [Contract Name]

## Contract Information
- **Name**: [Contract Name]
- **Address**: [If deployed]
- **Framework**: Foundry / Hardhat
- **Solidity Version**: [Version]
- **Inheritance Chain**: [Parent contracts]

## Functions Summary

| Function | Visibility | Modifiers | State Changes | Risk |
|----------|-----------|-----------|---------------|------|
| initialize | external | initializer | owner, settings | CRITICAL |
| deposit | external | nonReentrant | balances, supply | CRITICAL |
| withdraw | external | onlyOwner | balances, supply | CRITICAL |
| getBalance | view | — | none | LOW |

## Attack Surface Map

### Critical Entry Points (Require Deep Review)
1. `withdraw` - Fund extraction, reentrancy risk
2. `initialize` - Proxy initialization, reinit risk
3. `swap` - Price manipulation, slippage

### Red Flags
- [ ] Function with no access modifier
- [ ] Financial operation without nonReentrant
- [ ] Admin function without timelock
- [ ] Unprotected initializer
- [ ] Missing zero-address checks
```

## 5. Integration

### After Entry Point Analysis
1. **vulnerability-scanner** - Scan each entry point
2. **reentrancy-auditor** - Check all external calls
3. **access-control-reviewer** - Validate authorization
4. **defi-analyzer** - Analyze DeFi interactions
