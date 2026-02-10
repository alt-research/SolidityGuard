# DeFi Protocol Security Checklist

## AMM / DEX
- [ ] Constant product (x*y=k) or curve formula correctly implemented
- [ ] Slippage protection enforced (minAmountOut parameter)
- [ ] Transaction deadline parameter supported
- [ ] LP token mint/burn operations atomic
- [ ] No price manipulation via large single-sided swaps
- [ ] Fee calculation correct and doesn't overflow
- [ ] Reserves tracked correctly after each operation
- [ ] Front-running mitigation (commit-reveal or private mempool)

## Lending / Borrowing
- [ ] Interest rate model audited for edge cases
- [ ] Collateral factor / LTV validated (< 100%)
- [ ] Liquidation threshold correct (> collateral factor)
- [ ] Oracle manipulation resistant (TWAP, multi-source, Chainlink)
- [ ] Bad debt handling mechanism exists
- [ ] Borrow cap per market enforced
- [ ] Flash loan protection on governance-affecting operations
- [ ] Health factor calculation correct
- [ ] Interest accrual timing is manipulation-resistant

## Vault / Yield (ERC-4626)
- [ ] First depositor inflation attack mitigated (virtual offset or minimum)
- [ ] Donation attack prevented (independent asset tracking)
- [ ] Share calculation rounding favors vault (round down on deposit shares)
- [ ] Withdrawal rounding favors vault (round up on withdrawal assets)
- [ ] No dust left after full withdrawal
- [ ] Preview functions match actual behavior
- [ ] Total assets includes all yield sources

## Governance
- [ ] Timelock on proposal execution (min 24-48 hours)
- [ ] Flash loan resistant voting (snapshot-based, ERC20Votes)
- [ ] Minimum proposal threshold to prevent spam
- [ ] Guardian/veto mechanism for emergencies
- [ ] Quorum based on past supply snapshot
- [ ] No double-voting across tokens/positions

## Bridge / Cross-chain
- [ ] Message verification cryptographically secure
- [ ] Replay protection (nonce or message hash tracking)
- [ ] Rate limiting on large transfers
- [ ] Emergency pause mechanism
- [ ] Validator/relayer set management secure
- [ ] Token mapping verified (correct decimals, addresses)
- [ ] Timeout mechanism for stuck messages

## Staking
- [ ] Reward distribution proportional and gas-efficient
- [ ] No reward manipulation via flash deposits
- [ ] Unstaking period enforced
- [ ] Reward calculation doesn't overflow with large stakes
- [ ] No compounding errors in reward accumulation
