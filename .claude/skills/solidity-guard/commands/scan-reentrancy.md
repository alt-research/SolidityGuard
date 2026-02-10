---
name: solidity-guard:scan-reentrancy
description: Focused scan for reentrancy vulnerabilities in Solidity contracts
argument-hint: "[path-to-contracts]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Reentrancy Security Scan

Focused analysis of reentrancy vulnerabilities across all variants.

## Usage
```
/solidity-guard:scan-reentrancy ./contracts
```

## Checks
- ETH-001: Single-function Reentrancy (CRITICAL)
- ETH-002: Cross-function Reentrancy (CRITICAL)
- ETH-003: Cross-contract Reentrancy (HIGH)
- ETH-004: Read-only Reentrancy (HIGH)
- ETH-005: Cross-chain Reentrancy (HIGH)
- ETH-044: ERC-777 Reentrancy Hook (CRITICAL)
- ETH-081: Transient Storage Slot Collision (CRITICAL) — EIP-1153
- ETH-083: TSTORE Reentrancy Bypass (CRITICAL) — EIP-1153

## Quick Detection
```bash
# Find all external calls
rg -n "\.call\{|\.transfer\(|\.send\(|\.delegatecall\(" [path]

# Find state changes after external calls (CEI violation)
rg -n "\.call\{" [path] -A 10

# Check for ReentrancyGuard
rg -n "nonReentrant|ReentrancyGuard" [path]

# Check for TSTORE-based reentrancy guards (EIP-1153)
rg -n "tstore|tload|TSTORE|TLOAD|ReentrancyGuardTransient" [path]

# Run Slither reentrancy detectors
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events
```

## Reentrancy Patterns

### Single-function (ETH-001)
```solidity
// VULNERABLE - state update after external call
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // External call
    require(success);
    balances[msg.sender] -= amount;  // State update AFTER call
}

// SECURE - CEI pattern
function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State update BEFORE call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

### Cross-function (ETH-002)
```solidity
// VULNERABLE - shared state across functions
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}

function transfer(address to, uint amount) external {
    require(balances[msg.sender] >= amount);  // Reads stale state during reentrancy
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

### Read-only (ETH-004)
```solidity
// Contract A - has reentrancy during withdrawal
function withdraw() external {
    uint shares = balanceOf(msg.sender);
    // External call before state update
    (bool success, ) = msg.sender.call{value: sharesToETH(shares)}("");
    _burn(msg.sender, shares);
}

// Contract B - reads Contract A's state
function getPrice() external view returns (uint) {
    // This returns incorrect price during A's reentrancy
    return contractA.totalAssets() / contractA.totalSupply();
}
```

### TSTORE Reentrancy (ETH-081, ETH-083) — EIP-1153
```solidity
// VULNERABLE — TSTORE slot collision in delegatecall
library LibA {
    function lock() internal { assembly { tstore(0x01, 1) } }  // slot 0x01
}
library LibB {
    function lock() internal { assembly { tstore(0x01, 1) } }  // COLLISION!
}

// SECURE — namespaced transient storage
library LibA {
    bytes32 constant SLOT = keccak256("LibA.lock");
    function lock() internal { assembly { tstore(SLOT, 1) } }
}
```

For each external call found, verify:
1. State is updated BEFORE the call (CEI pattern)
2. ReentrancyGuard is applied
3. No cross-function paths share mutable state
4. No other protocols read this contract's state during calls
5. TSTORE-based locks use namespaced slots (not hardcoded 0x00, 0x01)
6. TSTORE guards not bypassable via delegatecall paths
