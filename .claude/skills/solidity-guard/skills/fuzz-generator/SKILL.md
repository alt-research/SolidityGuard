---
name: fuzz-generator
description: |
  Generates Foundry invariant tests and Echidna property-based fuzz tests for Solidity
  contracts. Creates handler contracts, invariant assertions, and fuzzing configurations.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
  - Bash
---

# Fuzz Test Generator

## 1. Purpose

Generate comprehensive fuzz tests using Foundry and Echidna. Fuzz testing finds edge cases and invariant violations that manual review and static analysis miss.

## 2. Foundry Invariant Tests

### Handler Pattern
```solidity
contract Handler is Test {
    MyContract target;
    uint256 public ghost_totalDeposited;

    constructor(MyContract _target) {
        target = _target;
    }

    function deposit(uint256 amount) public {
        amount = bound(amount, 1, 1e24);
        deal(address(this), amount);
        target.deposit{value: amount}();
        ghost_totalDeposited += amount;
    }

    function withdraw(uint256 amount) public {
        uint256 balance = target.balanceOf(address(this));
        amount = bound(amount, 0, balance);
        if (amount == 0) return;
        target.withdraw(amount);
        ghost_totalDeposited -= amount;
    }
}

contract InvariantTest is Test {
    MyContract target;
    Handler handler;

    function setUp() public {
        target = new MyContract();
        handler = new Handler(target);
        targetContract(address(handler));
    }

    function invariant_solvency() public {
        assertGe(
            address(target).balance,
            target.totalDeposits(),
            "Contract must be solvent"
        );
    }

    function invariant_totalSupply() public {
        assertEq(
            target.totalSupply(),
            handler.ghost_totalDeposited(),
            "Supply must match deposits"
        );
    }
}
```

## 3. Echidna Properties

```solidity
contract EchidnaTest is MyContract {
    constructor() MyContract() {}

    function echidna_solvency() public view returns (bool) {
        return address(this).balance >= totalDeposits;
    }

    function echidna_no_overflow() public view returns (bool) {
        return totalSupply <= type(uint256).max / 2;
    }
}
```

### Echidna Config (echidna.yaml)
```yaml
testMode: "property"
testLimit: 50000
seqLen: 100
shrinkLimit: 5000
deployer: "0x30000"
sender: ["0x10000", "0x20000", "0x30000"]
```

## 4. Common Invariants

### Financial
- Total assets >= total liabilities
- Sum of balances == total supply
- No individual balance exceeds total supply
- Withdrawal amount <= deposit amount

### Access Control
- Owner never changes without proper authorization
- Roles can't be self-assigned
- Admin actions require admin role

### State Machine
- Valid state transitions only
- No invalid intermediate states
- Monotonic counters only increase

## 5. Running

```bash
# Foundry invariant tests
forge test --match-test "invariant" -vvv --fuzz-runs 1000

# Echidna
echidna . --contract EchidnaTest --config echidna.yaml

# With corpus
echidna . --contract EchidnaTest --corpus-dir corpus/
```
