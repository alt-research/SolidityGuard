---
name: defi-analyzer
description: |
  Analyzes DeFi-specific security patterns in Solidity contracts. Covers oracle
  manipulation, flash loan attacks, economic exploits, vault inflation, MEV,
  and protocol-specific vulnerabilities.
allowed-tools:
  - Read
  - Grep
  - Glob
  - WebFetch
---

# DeFi Security Analyzer

## 1. Purpose

Detect economic and protocol-specific vulnerabilities unique to DeFi applications. These cause the largest financial losses but require semantic understanding beyond pattern matching.

## 2. Vulnerability Patterns

### ETH-024: Oracle Manipulation (CRITICAL)
**Loss Example**: Cream Finance $130M, Mango Markets $116M

```solidity
// VULNERABLE — spot price, single source
uint256 price = pool.getReserves();
uint256 value = amount * price;

// SECURE — TWAP + multi-oracle + staleness
(, int256 price, , uint256 updatedAt, ) = chainlinkFeed.latestRoundData();
require(updatedAt > block.timestamp - MAX_STALENESS, "Stale oracle");
require(price > 0, "Invalid price");
// Cross-reference with TWAP
uint256 twapPrice = uniswapOracle.consult(token, TWAP_PERIOD);
require(abs(price - twapPrice) < MAX_DEVIATION, "Price deviation");
```

### ETH-025: Flash Loan Attack (CRITICAL)
**Loss Example**: Beanstalk $182M, Harvest Finance $34M

```solidity
// VULNERABLE — governance votes based on current balance
uint256 votingPower = token.balanceOf(msg.sender);

// SECURE — snapshot-based voting
uint256 votingPower = token.getPastVotes(msg.sender, proposalSnapshot);
```

### ETH-057: Vault Share Inflation / First Depositor (CRITICAL)
**Loss Example**: Euler Finance $197M attack amplified by this

```solidity
// VULNERABLE — first depositor can inflate share price
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    // Attacker: deposit 1 wei, donate 1M tokens, next depositor gets 0 shares
}

// SECURE — virtual offset (ERC-4626 recommendation)
function _convertToShares(uint256 assets) internal view returns (uint256) {
    return assets.mulDiv(totalSupply() + 1, totalAssets() + 1);  // Virtual offset
}
```

### ETH-058: Donation Attack (HIGH)
Attacker donates tokens directly to contract to manipulate share price or accounting.

### ETH-026: Sandwich Attack / MEV (HIGH)
```solidity
// VULNERABLE — no slippage protection
function swap(uint amountIn) external {
    uint amountOut = calculateOutput(amountIn);
    token.transfer(msg.sender, amountOut);
}

// SECURE — user-specified minimum
function swap(uint amountIn, uint minAmountOut, uint deadline) external {
    require(block.timestamp <= deadline, "Expired");
    uint amountOut = calculateOutput(amountIn);
    require(amountOut >= minAmountOut, "Slippage exceeded");
    token.transfer(msg.sender, amountOut);
}
```

### ETH-094: Uniswap V4 Hook Callback Authorization (CRITICAL)
**Loss Example**: Cork Protocol $11M

```solidity
// VULNERABLE — hook doesn't verify caller
function afterSwap(
    address sender,
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    BalanceDelta delta,
    bytes calldata hookData
) external returns (bytes4, int128) {
    // Anyone can call this directly!
    _handleSwapLogic(key, delta, hookData);
}

// SECURE — verify msg.sender is PoolManager
function afterSwap(
    address sender,
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    BalanceDelta delta,
    bytes calldata hookData
) external override poolManagerOnly returns (bytes4, int128) {
    _handleSwapLogic(key, delta, hookData);
}

modifier poolManagerOnly() {
    require(msg.sender == address(poolManager), "Not PoolManager");
    _;
}
```

### ETH-095: Hook Data Manipulation (HIGH)
Attacker passes crafted `hookData` to manipulate hook behavior.

### ETH-096: Cached State Desynchronization (HIGH)
**Loss Example**: Yearn yETH $9M

```solidity
// VULNERABLE — cached price becomes stale after external call
function rebalance() external {
    uint256 price = oracle.getPrice();  // Cached
    _swapTokens(tokenA, tokenB, amount);  // External call changes state
    uint256 value = balance * price;  // Uses stale price!
}

// SECURE — re-read after external interaction
function rebalance() external {
    _swapTokens(tokenA, tokenB, amount);
    uint256 price = oracle.getPrice();  // Fresh read after interaction
    uint256 value = balance * price;
}
```

## 3. Protocol-Specific Checklists

### AMM/DEX
- [ ] Constant product formula correct
- [ ] Slippage protection enforced
- [ ] LP token mint/burn atomic
- [ ] No price manipulation via large swaps
- [ ] Fee calculation doesn't overflow
- [ ] Deadline parameter supported
- [ ] Uniswap V4 hooks verify `msg.sender == poolManager` (ETH-094)
- [ ] hookData validated and sanitized (ETH-095)

### Lending Protocol
- [ ] Interest rate model secure
- [ ] Collateral factor validated
- [ ] Liquidation threshold correct
- [ ] Oracle manipulation resistant (TWAP, multi-source)
- [ ] Bad debt handling
- [ ] Borrow limit enforced

### Vault (ERC-4626)
- [ ] First depositor attack mitigated (virtual offset or minimum deposit)
- [ ] Share inflation via donation prevented
- [ ] Rounding direction correct (favor vault)
- [ ] Withdrawal does not leave dust

### Governance
- [ ] Timelock on proposal execution (24-48h min)
- [ ] Flash loan resistant (snapshot voting)
- [ ] Minimum proposal threshold
- [ ] Guardian/veto mechanism for emergencies

### Bridge
- [ ] Message verification secure
- [ ] Replay protection (nonce or hash)
- [ ] Rate limiting
- [ ] Emergency pause mechanism
- [ ] Relayer validation

## 4. Detection Workflow

### Step 1: Identify Protocol Type
```bash
rg "swap|addLiquidity|removeLiquidity" contracts/  # AMM
rg "borrow|lend|liquidate|collateral" contracts/    # Lending
rg "deposit.*shares|withdraw.*assets|ERC4626" contracts/  # Vault
rg "propose|vote|execute|timelock" contracts/       # Governance
```

### Step 1b: Check Uniswap V4 / Hook Patterns
```bash
rg "IHooks|BaseHook|afterSwap|beforeSwap|afterModifyPosition" contracts/  # V4 hooks
rg "poolManager|PoolManager" contracts/  # Hook caller verification
rg "hookData" contracts/  # Data passed to hooks
```

### Step 2: Map Economic Flows
1. Where does value enter? (deposit, mint, borrow)
2. Where does value exit? (withdraw, burn, repay)
3. What determines prices/rates?
4. Who can trigger value transfers?
5. What oracles are used?
6. Are any values cached across external calls? (ETH-096)

### Step 3: Attack Surface Analysis
- Flash loan scenarios
- Oracle manipulation scenarios
- MEV extraction scenarios
- First depositor scenarios
- Uniswap V4 hook exploitation scenarios (ETH-094, ETH-095)
- Cached state desynchronization (ETH-096)

## 5. Real Exploit Case Studies

| Exploit | Loss | Pattern | Lesson |
|---------|------|---------|--------|
| The DAO | $60M | ETH-001 | CEI pattern, ReentrancyGuard |
| Cream Finance | $130M | ETH-024 | Multi-oracle, TWAP |
| Beanstalk | $182M | ETH-025 | Snapshot voting, timelock |
| Euler Finance | $197M | ETH-058 | Donation attack defense |
| Ronin Bridge | $625M | ETH-006 | Multi-sig threshold |
| Harvest Finance | $34M | ETH-024,025 | Flash loan oracle check |
| Cork Protocol | $11M | ETH-094 | Verify hook msg.sender |
| Yearn yETH | $9M | ETH-096 | Re-read state after calls |
| GMX V1 | $42M | ETH-024 | Multi-oracle + TWAP |
| Balancer V2 | $128M | ETH-004 | Reentrancy-aware view functions |
