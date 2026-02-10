---
name: solidity-guard:fuzz
description: Generate Foundry invariant tests and Echidna fuzz tests for Solidity contracts
argument-hint: "[path-to-contracts]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
---

# Fuzz Test Generator

Generate Foundry invariant tests and Echidna property-based tests for Solidity contracts.

## Usage
```
/solidity-guard:fuzz ./contracts
```

## Output
Creates fuzz test files with:
- Foundry invariant test contracts
- Echidna property contracts
- Handler contracts for stateful fuzzing
- Invariant assertions

## Foundry Invariant Test Template
```solidity
// test/invariant/MyContractInvariant.t.sol
contract MyContractInvariantTest is Test {
    MyContract target;
    Handler handler;

    function setUp() public {
        target = new MyContract();
        handler = new Handler(target);
        targetContract(address(handler));
    }

    // Total supply must equal sum of all balances
    function invariant_totalSupplyMatchesBalances() public {
        assertEq(target.totalSupply(), handler.ghost_totalBalance());
    }

    // No individual balance exceeds total supply
    function invariant_noBalanceExceedsTotalSupply() public {
        for (uint i = 0; i < handler.actorsCount(); i++) {
            assertLe(target.balanceOf(handler.actors(i)), target.totalSupply());
        }
    }
}
```

## Echidna Property Template
```solidity
contract MyContractEchidnaTest is MyContract {
    function echidna_total_supply_invariant() public view returns (bool) {
        return totalSupply() <= MAX_SUPPLY;
    }

    function echidna_no_free_tokens() public view returns (bool) {
        return balanceOf(address(this)) == 0 || totalDeposits > 0;
    }
}
```

## Running

```bash
# Foundry invariant tests
forge test --match-test "invariant" -vvv

# Echidna
echidna . --contract MyContractEchidnaTest --config echidna.yaml
```
