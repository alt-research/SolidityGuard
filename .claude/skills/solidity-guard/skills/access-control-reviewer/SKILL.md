---
name: access-control-reviewer
description: |
  Comprehensive access control and authorization review for Solidity contracts.
  Checks ownership, role-based access, proxy authorization, centralization risks,
  and privilege escalation vulnerabilities.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Access Control Reviewer

## 1. Purpose

Systematically validate access control in Solidity contracts. Access control failures are the #1 vulnerability category in 2025, responsible for $1.6B+ in losses.

## 2. Vulnerability Patterns

### ETH-006: Missing Access Control (CRITICAL)
State-changing function without any authorization check.

```solidity
// VULNERABLE
function setPrice(uint newPrice) external {
    price = newPrice;  // Anyone can call!
}

// SECURE
function setPrice(uint newPrice) external onlyOwner {
    price = newPrice;
}
```

### ETH-007: tx.origin Authentication (CRITICAL)
```solidity
// VULNERABLE — phishing attack via intermediate contract
require(tx.origin == owner);

// SECURE
require(msg.sender == owner);
```

### ETH-008: Unprotected selfdestruct (CRITICAL)
```solidity
// VULNERABLE
function destroy() external {
    selfdestruct(payable(msg.sender));
}

// SECURE
function destroy() external onlyOwner {
    selfdestruct(payable(owner));
}
```

### ETH-010: Uninitialized Proxy (CRITICAL)
Implementation contract not initialized, allowing anyone to take ownership.

### ETH-012: Centralization Risk (MEDIUM)
Single admin can change critical parameters without timelock or multisig.

### ETH-086: Broken tx.origin == msg.sender Assumption (CRITICAL) — EIP-7702
Post-Pectra, `tx.origin == msg.sender` no longer guarantees caller is an EOA. EOAs can have code via EIP-7702 delegation.

```solidity
// VULNERABLE — broken after EIP-7702 (Pectra upgrade)
require(tx.origin == msg.sender, "No contracts");
// EOA with delegated code passes this check but executes arbitrary logic!

// SECURE — use ERC-165 or explicit whitelist
// Or: accept that EOAs can have code and design accordingly
```

### ETH-088: EIP-7702 Cross-Chain Authorization Replay (CRITICAL)
EIP-7702 authorization tuples can be replayed on other chains if chain ID is not validated.

```solidity
// VULNERABLE — no chain ID in authorization validation
function setDelegation(address delegate, bytes calldata sig) external {
    // Missing: chainId check in signature verification
}

// SECURE — always include chain ID in EIP-7702 authorization
// The protocol enforces this, but custom implementations may not
```

### ETH-091: Paymaster Exploitation (CRITICAL) — ERC-4337
Paymaster sponsors gas but doesn't validate actual execution cost or effects.

```solidity
// VULNERABLE — paymaster pays for any UserOp
function validatePaymasterUserOp(UserOperation calldata userOp, ...)
    external returns (bytes memory context, uint256 validationData) {
    return ("", 0);  // Approves everything!
}

// SECURE — validate user, op limits, and track spending
function validatePaymasterUserOp(UserOperation calldata userOp, ...)
    external returns (bytes memory context, uint256 validationData) {
    require(approvedUsers[userOp.sender], "Not approved");
    require(userOp.callGasLimit <= MAX_GAS, "Gas too high");
    require(dailySpend[userOp.sender] + cost <= DAILY_LIMIT, "Limit exceeded");
    // ...
}
```

### ETH-093: Validation-Execution Phase Confusion (CRITICAL) — ERC-4337
Validation phase has side effects that affect execution phase, violating ERC-4337 separation.

## 3. Audit Workflow

### Step 1: Map All State-changing Functions
```bash
rg "function.*(external|public)" contracts/ | grep -v "view\|pure"
```

### Step 2: Check Access Control
For each state-changing function, verify:
- [ ] Has `onlyOwner`, `onlyRole`, or custom access modifier
- [ ] Uses `msg.sender` not `tx.origin`
- [ ] Does NOT rely on `tx.origin == msg.sender` to detect EOA (EIP-7702 breaks this)
- [ ] Initializer has `initializer` modifier
- [ ] Upgrade functions have proper authorization
- [ ] ERC-4337 UserOp validation doesn't have side effects

### Step 3: Map Privilege Hierarchy
```
Owner / Admin
  ├── Can: pause, unpause, upgrade, setFee
  ├── Should have: timelock, multisig
  │
Operator / Manager
  ├── Can: harvest, rebalance
  │
User
  └── Can: deposit, withdraw, claim
```

### Step 4: Check Proxy Patterns
```bash
rg "initializer|_disableInitializers|__gap" contracts/
rg "upgradeTo|upgradeToAndCall|_authorizeUpgrade" contracts/
```

### Step 5: Check EIP-7702 / ERC-4337 Patterns
```bash
rg "tx\.origin.*==.*msg\.sender|msg\.sender.*==.*tx\.origin" contracts/  # ETH-086
rg "extcodesize|isContract" contracts/  # ETH-089 — unreliable post-7702
rg "IPaymaster|validatePaymasterUserOp|UserOperation" contracts/  # ETH-091
rg "validateUserOp|IAccount" contracts/  # ETH-093
```

## 4. OpenZeppelin Patterns

### Ownable
```solidity
import "@openzeppelin/contracts/access/Ownable.sol";
// Single owner, transferable
```

### AccessControl (RBAC)
```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";
// Role-based, granular permissions
bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
```

### Ownable2Step
```solidity
import "@openzeppelin/contracts/access/Ownable2Step.sol";
// Two-step ownership transfer (safer)
```

## 5. Quick Checklist

- [ ] All state-changing functions have access control
- [ ] No `tx.origin` for authentication
- [ ] No `tx.origin == msg.sender` to detect EOA (broken by EIP-7702)
- [ ] No `extcodesize == 0` to detect EOA (broken by EIP-7702)
- [ ] No unprotected `selfdestruct`
- [ ] Proxy implementations are initialized or disabled
- [ ] Upgrade functions are properly authorized
- [ ] Critical operations have timelock
- [ ] Admin keys use multisig
- [ ] Two-step ownership transfer used
- [ ] ERC-4337 paymaster validates user and limits (ETH-091)
- [ ] ERC-4337 validation phase has no side effects (ETH-093)
