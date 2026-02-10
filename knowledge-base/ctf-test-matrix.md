# CTF Test Matrix — SolidityGuard Pattern Validation

Maps CTF challenges and exploit reproduction repos to SolidityGuard ETH-xxx vulnerability patterns. Used to benchmark scanner detection accuracy.

## Scanner Coverage Summary

| Metric | Value |
|--------|-------|
| Total ETH patterns | 104 |
| Scanner-detectable (scan_patterns) | 17 |
| CTF unit tests (test_scanners.py) | 26 |
| DeFiVulnLabs mappings | 31 |
| Unique patterns tested via CTF | 28 |

## Tier 1: DeFiVulnLabs (SunWeb3Sec)

**Repository**: https://github.com/SunWeb3Sec/DeFiVulnLabs
**Type**: 48 isolated Foundry vulnerability demonstrations
**Best for**: Unit-level scanner validation — one vulnerability per contract

| DeFiVulnLabs Contract | ETH Pattern | Category | Scanner Detects? |
|----------------------|-------------|----------|-----------------|
| Reentrancy.sol | ETH-001 | Reentrancy | Partial (needs CEI check) |
| Reentrancy-read-only.sol | ETH-004 | Reentrancy | No (needs semantic analysis) |
| Selfdestruct.sol | ETH-008 | Access Control | **Yes** |
| Txorigin.sol | ETH-007 | Access Control | **Yes** |
| Overflow.sol | ETH-013, ETH-072 | Arithmetic | **Yes** (unchecked + old pragma) |
| UncheckedReturnValue.sol | ETH-018 | External Calls | **Yes** (with lookahead) |
| Delegatecall.sol | ETH-019 | External Calls | **Yes** |
| Randomness.sol | ETH-037 | Logic | **Yes** (context-aware) |
| Dos.sol | ETH-066 | Gas & DoS | Partial (loop detection) |
| SignatureReplay.sol | ETH-039 | Logic | No (needs ecrecover check) |
| Visibility.sol | ETH-009 | Access Control | No (needs visibility parse) |
| PrivateData.sol | ETH-078 | Miscellaneous | No (needs pattern) |
| ERC20.sol | ETH-041 | Token | No (needs SafeERC20 check) |
| Frontrunning.sol | ETH-040 | Logic | No (semantic) |
| ApproveScam.sol | ETH-046 | Token | No (semantic) |
| Encodepacked.sol | ETH-073 | Miscellaneous | **Yes** |
| Oracle.sol | ETH-024 | Oracle | No (needs oracle pattern) |
| Flashloan.sol | ETH-025 | Oracle | No (semantic) |
| StorageCollision.sol | ETH-030 | Storage | No (needs layout analysis) |
| Vault.sol | ETH-057 | DeFi | No (needs ERC4626 check) |
| Slippage.sol | ETH-027 | DeFi | No (needs slippage check) |
| fee-on-transfer.sol | ETH-042 | Token | No (semantic) |
| Array-deletion.sol | ETH-029 | Storage | No (needs pattern) |
| GasGriefing.sol | ETH-023, ETH-069 | Gas & DoS | No (needs gas forwarding check) |
| Bypasscontract.sol | ETH-089 | Access Control | **Yes** (extcodesize) |
| DataLocation.sol | ETH-029 | Storage | No (needs data location check) |
| HiddenMint.sol | ETH-048 | Token | No (semantic) |
| Stacking.sol | ETH-063 | DeFi | No (semantic) |
| DirtybytesEXP.sol | ETH-097 | Miscellaneous | No (compiler-specific) |
| EtherBalance.sol | ETH-034 | Logic | No (needs equality check) |
| Erc777-reentrancy.sol | ETH-044 | Token | No (needs hook detection) |

**Current detection rate**: ~10/31 contracts (32%) via pattern scanner alone.
**With Slither+Aderyn**: estimated 22/31 (71%).

## Tier 2: DeFiHackLabs (SunWeb3Sec)

**Repository**: https://github.com/SunWeb3Sec/DeFiHackLabs
**Type**: 700+ real-world exploit reproductions in Foundry
**Best for**: Regression testing against real exploits

### Key Exploits Mapped to ETH Patterns

| Exploit | Year | Loss | ETH Pattern(s) | Foundry Test |
|---------|------|------|----------------|-------------|
| Bybit | 2025 | $1.5B | ETH-101 (off-chain) | N/A (off-chain) |
| UPCX | 2025 | $70M | ETH-052 | src/test/2025-04/UPCX_exp.sol |
| Phemex | 2025 | $73M | ETH-006 | src/test/2025-01/Phemex_exp.sol |
| SIR.trading | 2025 | $355K | ETH-081 | src/test/2025-03/SIR_exp.sol |
| Cork Protocol | 2025 | $11M | ETH-094 | src/test/2025-02/Cork_exp.sol |
| Yearn yETH | 2025 | $9M | ETH-096 | src/test/2025-01/Yearn_exp.sol |
| Radiant Capital | 2024 | $50M | ETH-006, ETH-038 | src/test/2024-10/Radiant_exp.sol |
| Munchables | 2024 | $62.5M | ETH-006 | src/test/2024-03/Munchables_exp.sol |
| Euler Finance | 2023 | $197M | ETH-058 | src/test/2023-03/Euler_exp.sol |
| Beanstalk | 2022 | $182M | ETH-025, ETH-055 | src/test/2022-04/Beanstalk_exp.sol |
| Ronin Bridge | 2022 | $625M | ETH-006 | src/test/2022-03/Ronin_exp.sol |
| Nomad Bridge | 2022 | $190M | ETH-029 | src/test/2022-08/Nomad_exp.sol |
| Cream Finance | 2021 | $130M | ETH-024 | src/test/2021-10/Cream_exp.sol |
| Rari/Fei | 2022 | $80M | ETH-001 | src/test/2022-04/Rari_exp.sol |

## Tier 3: Damn Vulnerable DeFi v4

**Repository**: https://github.com/tinchoabbate/damn-vulnerable-defi
**Type**: 18 progressive DeFi security challenges (Foundry native)
**Best for**: Complex multi-step exploit validation

| Challenge | ETH Pattern(s) | Difficulty |
|-----------|----------------|-----------|
| 1. Unstoppable | ETH-034 (strict balance equality) | Easy |
| 2. Naive Receiver | ETH-018, ETH-023 (unchecked call, gas griefing) | Easy |
| 3. Truster | ETH-006, ETH-019 (missing auth, delegatecall) | Easy |
| 4. Side Entrance | ETH-001 (reentrancy via flash loan callback) | Easy |
| 5. The Rewarder | ETH-025, ETH-063 (flash loan, reward error) | Medium |
| 6. Selfie | ETH-025, ETH-055 (flash loan governance) | Medium |
| 7. Compromised | ETH-024 (oracle manipulation) | Medium |
| 8. Puppet | ETH-024, ETH-025 (oracle + flash loan) | Medium |
| 9. Puppet V2 | ETH-024, ETH-025 (Uniswap V2 oracle) | Medium |
| 10. Free Rider | ETH-001, ETH-025 (reentrancy + flash swap) | Hard |
| 11. Backdoor | ETH-019, ETH-006 (delegatecall, hidden setup) | Hard |
| 12. Climber | ETH-006, ETH-052 (access control, upgrade) | Hard |
| 13. Wallet Mining | ETH-049, ETH-019 (uninit impl, delegatecall) | Hard |
| 14. Puppet V3 | ETH-024 (Uniswap V3 oracle TWAP) | Hard |
| 15. ABI Smuggling | ETH-098 (input validation bypass) | Hard |
| 16. Shards | ETH-016, ETH-057 (rounding, share inflation) | Hard |
| 17. Withdrawal | ETH-003, ETH-005 (cross-contract, L2 bridge) | Hard |
| 18. Curvy Puppet | ETH-024, ETH-025 (Curve oracle + flash loan) | Expert |

## Tier 4: Ethernaut (OpenZeppelin)

**Repository**: https://github.com/OpenZeppelin/ethernaut
**Type**: 32 progressive wargame levels
**Best for**: Foundational Solidity security concepts

| Level | Name | ETH Pattern(s) |
|-------|------|----------------|
| 0 | Hello Ethernaut | — (tutorial) |
| 1 | Fallback | ETH-006 (missing access control) |
| 2 | Fallout | ETH-080 (incorrect constructor) |
| 3 | Coin Flip | ETH-037 (weak randomness) |
| 4 | Telephone | ETH-007 (tx.origin) |
| 5 | Token | ETH-013 (integer overflow) |
| 6 | Delegation | ETH-019 (delegatecall) |
| 7 | Force | ETH-032, ETH-034 (unexpected ether) |
| 8 | Vault | ETH-078 (private data on-chain) |
| 9 | King | ETH-021 (DoS with failed call) |
| 10 | Re-entrancy | ETH-001 (reentrancy) |
| 11 | Elevator | ETH-064 (insecure callback) |
| 12 | Privacy | ETH-078 (storage layout) |
| 13 | Gatekeeper One | ETH-007, ETH-023 (tx.origin, gas) |
| 14 | Gatekeeper Two | ETH-089 (extcodesize bypass) |
| 15 | Naught Coin | ETH-041 (ERC-20 non-standard) |
| 16 | Preservation | ETH-019, ETH-030 (delegatecall, storage) |
| 17 | Recovery | ETH-045 (address recovery) |
| 18 | MagicNumber | — (bytecode challenge) |
| 19 | Alien Codex | ETH-033 (arbitrary storage write) |
| 20 | Denial | ETH-021, ETH-066 (DoS, gas limit) |
| 21 | Shop | ETH-064 (insecure callback) |
| 22 | Dex | ETH-024 (oracle manipulation) |
| 23 | Dex Two | ETH-024, ETH-041 (oracle, token) |
| 24 | Puzzle Wallet | ETH-019, ETH-030 (proxy, storage collision) |
| 25 | Motorbike | ETH-049, ETH-052 (uninit impl, upgrade) |
| 26 | DoubleEntryPoint | ETH-003 (cross-contract) |
| 27 | Good Samaritan | ETH-064 (custom error callback) |
| 28 | Gatekeeper Three | ETH-007, ETH-034 (tx.origin, balance) |
| 29 | Switch | ETH-098 (calldata manipulation) |
| 30 | HigherOrder | ETH-098 (type confusion) |
| 31 | Stake | ETH-018, ETH-034 (unchecked return, balance) |

## Tier 5: Mr Steal Yo Crypto

**Repository**: https://github.com/0xToshii/mr-steal-yo-crypto-ctf-foundry
**Type**: 20 DeFi-focused challenges with Foundry framework
**Best for**: Advanced DeFi vulnerability validation

| Challenge | ETH Pattern(s) |
|-----------|----------------|
| 1. jpeg-sniper | ETH-040 (front-running NFT mint) |
| 2. safu-vault | ETH-057 (vault share inflation) |
| 3. freebie | ETH-006 (missing access control) |
| 4. side-entrance | ETH-001, ETH-025 (reentrancy + flash loan) |
| 5. tasty-stake | ETH-063 (reward distribution error) |
| 6. game-assets | ETH-044 (ERC-1155 reentrancy) |
| 7. crystal-casino | ETH-037 (weak randomness) |
| 8. bonding-curve | ETH-059 (AMM math error) |
| 9. governance-shenanigans | ETH-025, ETH-055 (flash loan governance) |
| 10. dex-2 | ETH-024 (oracle manipulation) |

## Pattern Coverage Matrix

Shows which CTF sources cover each ETH pattern category:

| Category | DeFiVulnLabs | DVDv4 | Ethernaut | MrSteal | DeFiHackLabs |
|----------|:------------:|:-----:|:---------:|:-------:|:------------:|
| Reentrancy (001-005) | 2 | 4 | 2 | 2 | 50+ |
| Access Control (006-012) | 3 | 3 | 4 | 1 | 100+ |
| Arithmetic (013-017) | 1 | 1 | 1 | — | 30+ |
| External Calls (018-023) | 2 | 2 | 2 | — | 40+ |
| Oracle/Price (024-028) | 3 | 5 | 2 | 2 | 80+ |
| Storage (029-033) | 3 | — | 3 | — | 20+ |
| Logic (034-040) | 3 | — | 3 | 2 | 60+ |
| Token (041-048) | 5 | — | 2 | 1 | 50+ |
| Proxy (049-054) | — | 2 | 2 | — | 30+ |
| DeFi (055-065) | 3 | 4 | 1 | 3 | 100+ |
| Gas/DoS (066-070) | 2 | — | 2 | — | 10+ |
| Misc (071-080) | 2 | — | 1 | — | 5+ |
| Transient Storage (081-085) | — | — | — | — | 1 |
| EIP-7702 (086-089) | 1 | — | 1 | — | — |
| ERC-4337 (090-093) | — | — | — | — | 2+ |
| Uniswap V4 (094-097) | — | — | — | — | 1 |
| Input Validation (098-099) | — | 2 | 2 | — | 10+ |
| Off-Chain (100-101) | — | — | — | — | 5+ |
| Restaking/L2 (102-104) | — | 1 | — | — | 3+ |

## Running the Benchmark

```bash
# Dry run — show mapping only (no network)
python3 ctf_benchmark.py --dry-run

# Full benchmark — clone and scan
python3 ctf_benchmark.py

# Use existing clone
python3 ctf_benchmark.py --repo-path /tmp/DeFiVulnLabs

# Save results as JSON
python3 ctf_benchmark.py --output benchmark-results.json
```

## Improving Detection Rate

Priority patterns to implement for maximum CTF coverage improvement:

| Priority | ETH Pattern | Expected Gain | Implementation |
|----------|-------------|---------------|----------------|
| 1 | ETH-001 (CEI reentrancy) | +3 contracts | Check `.call{value:` before state update |
| 2 | ETH-039 (signature replay) | +1 contract | Check ecrecover without nonce mapping |
| 3 | ETH-024 (oracle manipulation) | +3 contracts | Detect single-source price feeds |
| 4 | ETH-034 (strict equality) | +1 contract | Check `== address(this).balance` |
| 5 | ETH-041 (ERC-20 returns) | +2 contracts | Check raw IERC20 calls without SafeERC20 |
| 6 | ETH-057 (vault inflation) | +1 contract | Check ERC4626 without virtual shares |
| 7 | ETH-009 (default visibility) | +1 contract | Check functions without explicit visibility |
| 8 | ETH-029 (uninitialized storage) | +2 contracts | Check `storage` pointer without init |

Implementing these 8 patterns would raise DeFiVulnLabs detection from ~32% to ~58%.
