---
name: reentrancy-auditor
description: |
  Deep reentrancy vulnerability analysis for Solidity contracts. Covers single-function,
  cross-function, cross-contract, and read-only reentrancy. Maps all external call paths
  and validates CEI pattern compliance.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Reentrancy Auditor

## 1. Purpose

Detect all variants of reentrancy vulnerabilities in Solidity contracts. Reentrancy is the #1 cause of DeFi exploits historically, responsible for The DAO ($60M), Rari Capital ($80M), and many others.

## 2. Reentrancy Variants

### ETH-001: Single-function Reentrancy (CRITICAL)
State update occurs after external call within the same function.

```solidity
// VULNERABLE
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // STATE AFTER CALL
}

// SECURE (CEI Pattern)
function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // STATE BEFORE CALL
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

### ETH-002: Cross-function Reentrancy (CRITICAL)
Multiple functions share state, and reentrancy through one corrupts another.

```solidity
// VULNERABLE — attacker reenters transfer() during withdraw()
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}

function transfer(address to, uint amount) external {
    require(balances[msg.sender] >= amount);  // Stale during reentrancy!
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

### ETH-003: Cross-contract Reentrancy (HIGH)
External call in Contract A allows reentry into Contract B that reads A's stale state.

### ETH-004: Read-only Reentrancy (HIGH)
View functions return incorrect values during reentrancy, affecting other protocols.

```solidity
// Contract A
function withdraw() external {
    uint shares = balanceOf(msg.sender);
    (bool s, ) = msg.sender.call{value: sharesToETH(shares)}("");
    _burn(msg.sender, shares);  // Burns AFTER call
}

// Contract B reads A's state during A's reentrancy
function getPrice() external view returns (uint) {
    return contractA.totalAssets() / contractA.totalSupply();  // Wrong during reentrancy!
}
```

### ETH-044: ERC-777 Reentrancy Hook (CRITICAL)
ERC-777 tokens call `tokensReceived` hook on recipient, allowing reentrancy.

### ETH-081: Transient Storage Slot Collision (CRITICAL)
Multiple contracts share the same transient storage slot via delegatecall, corrupting reentrancy guards.

```solidity
// VULNERABLE — two libraries use same TSTORE slot
library LibA {
    bytes32 constant LOCK_SLOT = 0x01;
    function lock() internal { assembly { tstore(LOCK_SLOT, 1) } }
}
library LibB {
    bytes32 constant LOCK_SLOT = 0x01;  // COLLISION!
    function lock() internal { assembly { tstore(LOCK_SLOT, 1) } }
}

// SECURE — use namespaced transient slots
library LibA {
    bytes32 constant LOCK_SLOT = keccak256("LibA.reentrancy.lock");
    function lock() internal { assembly { tstore(LOCK_SLOT, 1) } }
}
```

### ETH-083: TSTORE Reentrancy Bypass (CRITICAL)
Reentrancy lock implemented via TSTORE can be bypassed if attacker enters with low gas that causes the TSTORE to fail silently or via cross-contract paths.

```solidity
// VULNERABLE — TSTORE-based lock without TLOAD check
modifier nonReentrant() {
    assembly {
        if tload(0x00) { revert(0, 0) }
        tstore(0x00, 1)
    }
    _;
    assembly { tstore(0x00, 0) }
}
// Cross-contract call may bypass if callee uses delegatecall

// SECURE — use OpenZeppelin's ReentrancyGuardTransient
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
```

## 3. Detection Workflow

### Step 1: Find All External Calls
```bash
rg -n "\.call\{|\.call\(|\.transfer\(|\.send\(|\.delegatecall\(" contracts/
rg -n "safeTransfer|safeTransferFrom" contracts/
rg -n "IERC20\(.*\)\.(transfer|transferFrom)" contracts/
rg -n "tstore|tload|TSTORE|TLOAD" contracts/  # Transient storage reentrancy guards
```

### Step 2: For Each External Call
1. Identify state variables modified in the same function
2. Check if state updates happen BEFORE the external call (CEI)
3. Check if `nonReentrant` modifier is applied
4. Map other functions that read/write the same state variables

### Step 3: Check for Cross-function Paths
```bash
# Find shared state variables
rg "mapping.*balances|mapping.*deposits|mapping.*shares" contracts/
# Then check all functions that read/write these
```

### Step 4: Check for Read-only Reentrancy
```bash
# Find view functions that calculate based on contract state
rg "function.*view.*returns" contracts/
# Check if these are used by external protocols
```

## 4. Secure Patterns

### ReentrancyGuard (OpenZeppelin)
```solidity
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw(uint amount) external nonReentrant {
        // Protected
    }
}
```

### CEI Pattern (Checks-Effects-Interactions)
```solidity
function withdraw(uint amount) external {
    // 1. CHECKS
    require(balances[msg.sender] >= amount, "Insufficient");

    // 2. EFFECTS (state changes)
    balances[msg.sender] -= amount;

    // 3. INTERACTIONS (external calls)
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

## 5. Finding Format

```markdown
## [CRITICAL] ETH-001: Reentrancy in withdraw()

**Location**: `contracts/Vault.sol:45`
**Confidence**: 0.95

### Evidence
State update at line 48 occurs AFTER external call at line 46:
```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // line 46
    require(success);
    balances[msg.sender] -= amount;  // line 48 — AFTER call!
}
```

### Attack Scenario
1. Attacker deposits 1 ETH
2. Attacker calls withdraw(1 ether)
3. Vault sends ETH via .call{} — triggers attacker's receive()
4. receive() re-enters withdraw() — balance still shows 1 ETH
5. Repeat until vault drained

### Recommendation
```solidity
function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // Update BEFORE call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```
```

## 6. Quick Checklist

- [ ] ALL external calls (.call, .transfer, .send) have state updated BEFORE
- [ ] nonReentrant modifier on ALL state-changing functions with external calls
- [ ] No cross-function paths share mutable state with external calls
- [ ] ERC-777 token interactions use ReentrancyGuard
- [ ] Flash loan callbacks follow CEI pattern
- [ ] View functions not affected by incomplete state during calls
- [ ] TSTORE-based reentrancy locks use namespaced slots (ETH-081)
- [ ] TSTORE lock not bypassable via delegatecall (ETH-083, ETH-084)
- [ ] If using ReentrancyGuardTransient, verify OZ version >= 5.1
