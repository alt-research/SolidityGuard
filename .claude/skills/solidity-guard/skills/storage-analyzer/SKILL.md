---
name: storage-analyzer
description: |
  Analyzes storage layout, proxy patterns, and state variable security in Solidity
  contracts. Detects storage collisions, uninitialized pointers, and upgrade risks.
  Use when auditing proxy/upgradeable contracts.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Storage Analyzer

## 1. Purpose

Detect storage-related vulnerabilities in Solidity contracts, especially proxy/upgradeable patterns. Storage issues are among the most severe and hardest to detect.

## 2. Vulnerability Patterns

### ETH-029: Uninitialized Storage Pointer (HIGH)
```solidity
// VULNERABLE (Solidity < 0.5.0)
function processData() external {
    Data data;  // Uninitialized — points to storage slot 0!
    data.value = msg.value;  // Overwrites slot 0 (owner!)
}
```

### ETH-030: Storage Collision in Proxy (CRITICAL)
```solidity
// Implementation V1
contract V1 {
    address public owner;     // slot 0
    uint256 public value;     // slot 1
}

// Implementation V2 — WRONG: changed layout
contract V2 {
    uint256 public value;     // slot 0 — COLLISION with owner!
    address public owner;     // slot 1
    uint256 public newField;  // slot 2
}

// CORRECT V2 — append only
contract V2 {
    address public owner;     // slot 0 (unchanged)
    uint256 public value;     // slot 1 (unchanged)
    uint256 public newField;  // slot 2 (new, appended)
}
```

### ETH-031: Shadowing State Variables (MEDIUM)
```solidity
contract Parent {
    uint256 public value;
}

contract Child is Parent {
    uint256 public value;  // Shadows Parent.value!
}
```

### ETH-032: Unexpected Ether Balance (MEDIUM)
```solidity
// VULNERABLE — relies on exact balance
require(address(this).balance == expectedBalance);
// Attacker can force-send ETH via selfdestruct
```

### ETH-050: Storage Layout Mismatch on Upgrade (CRITICAL)
Changing variable order, types, or removing variables between upgrade versions.

### ETH-081: Transient Storage Slot Collision (CRITICAL)
```solidity
// VULNERABLE — shared transient slot across delegatecall
contract Base {
    function _lock() internal {
        assembly { tstore(0x00, 1) }  // Slot 0x00
    }
}
contract Extension {
    function _check() internal {
        assembly { tstore(0x00, 1) }  // COLLISION via delegatecall!
    }
}

// SECURE — namespaced transient storage slots
bytes32 constant LOCK_SLOT = keccak256("myprotocol.base.lock");
assembly { tstore(LOCK_SLOT, 1) }
```

### ETH-082: Transient Storage Not Cleared (HIGH)
Transient storage is automatically cleared at end of transaction, but within a transaction values persist across internal calls. Relying on "clean" transient state within a tx can be dangerous.

### ETH-084: Transient Storage Delegatecall Exposure (HIGH)
Delegatecall shares transient storage context with caller, allowing callee to read/write caller's transient slots.

```solidity
// VULNERABLE — callee reads caller's transient lock state
contract Caller {
    function execute(address target) external {
        assembly { tstore(0x01, 42) }  // Set transient state
        target.delegatecall(abi.encodeWithSignature("run()"));
        // Target can read/write slot 0x01!
    }
}
```

## 3. Proxy Pattern Analysis

### Step 0: Check Transient Storage Usage (EIP-1153)
```bash
rg "tstore|tload|TSTORE|TLOAD" contracts/  # Direct assembly
rg "ReentrancyGuardTransient" contracts/  # OZ transient guard
rg "transient" contracts/  # Solidity 0.8.28+ transient keyword
```

### Step 1: Identify Proxy Type
```bash
rg "ERC1967|TransparentUpgradeableProxy|UUPSUpgradeable|Beacon" contracts/
rg "delegatecall|fallback\(\)|_implementation\(\)" contracts/
```

### Step 2: Check Storage Gap
```bash
rg "__gap|uint256\[.*\].*gap" contracts/
```

### Step 3: Verify Initializer
```bash
rg "initializer|_disableInitializers|initialized" contracts/
```

### Step 4: Compare Storage Layouts
```bash
# Using Foundry
forge inspect ContractV1 storage-layout --pretty
forge inspect ContractV2 storage-layout --pretty
# Compare outputs for mismatches
```

## 4. Secure Patterns

### Storage Gap
```solidity
contract V1 is Initializable {
    address public owner;
    uint256 public value;
    uint256[48] private __gap;  // Reserve slots for future
}
```

### ERC-7201 Namespaced Storage
```solidity
// Modern approach — prevents collisions
library StorageLib {
    bytes32 constant STORAGE_SLOT = keccak256("myprotocol.storage.main");

    struct Storage {
        address owner;
        uint256 value;
    }

    function getStorage() internal pure returns (Storage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }
}
```

## 5. Quick Checklist

- [ ] No uninitialized storage pointers (Solidity >= 0.5.0)
- [ ] Proxy storage layout consistent across versions
- [ ] Storage gaps in upgradeable base contracts
- [ ] No variable reordering between versions
- [ ] No strict equality checks on ETH balance
- [ ] Implementation contract initialized or disabled
- [ ] No shadowed state variables in inheritance
- [ ] Transient storage slots namespaced per contract/library (ETH-081)
- [ ] Transient storage cleared or reset assumptions documented (ETH-082)
- [ ] Delegatecall contracts don't share transient slots unsafely (ETH-084)
