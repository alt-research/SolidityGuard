# SolidityGuard Vulnerability Patterns Reference

## 104 Patterns (ETH-001 to ETH-104)

### Reentrancy (ETH-001 to ETH-005)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-001 | Single-function Reentrancy | CRITICAL | External call before state update in same function |
| ETH-002 | Cross-function Reentrancy | CRITICAL | Shared state modified after external call in different function |
| ETH-003 | Cross-contract Reentrancy | HIGH | State dependency between contracts with external calls |
| ETH-004 | Read-only Reentrancy | HIGH | View function called during state transition |
| ETH-005 | Cross-chain Reentrancy | HIGH | Bridge callback exploiting pending state |

### Access Control (ETH-006 to ETH-012)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-006 | Missing Access Control | CRITICAL | State-changing function without access modifier |
| ETH-007 | tx.origin Authentication | CRITICAL | `tx.origin` used for authorization |
| ETH-008 | Unprotected selfdestruct | CRITICAL | `selfdestruct` callable by non-owner |
| ETH-009 | Default Function Visibility | HIGH | Missing visibility specifier |
| ETH-010 | Uninitialized Proxy | CRITICAL | Public `initialize()` without `initializer` modifier |
| ETH-011 | Missing Modifier on State Change | HIGH | Public function modifies state without auth |
| ETH-012 | Centralization Risk | MEDIUM | Single admin key controls critical functions |

### Arithmetic (ETH-013 to ETH-017)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-013 | Integer Overflow/Underflow | HIGH | Arithmetic in `unchecked` block or Solidity <0.8 |
| ETH-014 | Division Before Multiplication | MEDIUM | `a / b * c` pattern causing precision loss |
| ETH-015 | Unchecked Math | HIGH | `unchecked` block with user-controlled values |
| ETH-016 | Rounding Errors | MEDIUM | Division truncation in token/share calculations |
| ETH-017 | Precision Loss | MEDIUM | Intermediate calculation loses significant digits |

### External Calls (ETH-018 to ETH-023)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-018 | Unchecked Return Value | HIGH | `.call()` return value not checked |
| ETH-019 | Delegatecall to Untrusted | CRITICAL | `delegatecall` with user-controlled address |
| ETH-020 | Unsafe Low-level Call | HIGH | Direct `.call()` instead of interface call |
| ETH-021 | DoS with Failed Call | HIGH | Loop with external call that can revert |
| ETH-022 | ERC-20 Return Not Checked | HIGH | `transfer()`/`transferFrom()` without SafeERC20 |
| ETH-023 | Insufficient Gas Griefing | MEDIUM | Forwarding limited gas to external call |

### Oracle & Price (ETH-024 to ETH-028)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-024 | Oracle Manipulation | CRITICAL | Single price source, no TWAP |
| ETH-025 | Flash Loan Attack | CRITICAL | Price/balance check exploitable in same block |
| ETH-026 | Sandwich/MEV | HIGH | Swap without slippage + deadline |
| ETH-027 | Missing Slippage Protection | HIGH | `amountOutMin = 0` or no minimum |
| ETH-028 | Stale Oracle Data | HIGH | No freshness check on Chainlink data |

### Storage & State (ETH-029 to ETH-033)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-029 | Uninitialized Storage Pointer | HIGH | Local storage variable without assignment |
| ETH-030 | Storage Collision | CRITICAL | Proxy and implementation storage layout mismatch |
| ETH-031 | Shadowing State Variables | MEDIUM | Child contract shadows parent state variable |
| ETH-032 | Unexpected Ether Balance | MEDIUM | `address(this).balance` in strict equality/logic |
| ETH-033 | Arbitrary Storage Write | CRITICAL | Computed `sstore` slot from user input |

### Logic Errors (ETH-034 to ETH-040)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-034 | Strict Equality on Balance | HIGH | `require(balance == x)` pattern |
| ETH-035 | Transaction Order Dependence | HIGH | State depends on transaction ordering |
| ETH-036 | Timestamp Dependence | MEDIUM | `block.timestamp` in critical logic |
| ETH-037 | Weak Randomness | HIGH | `block.timestamp`/`blockhash` as entropy |
| ETH-038 | Signature Malleability | HIGH | ECDSA without `s` value check |
| ETH-039 | Signature Replay | CRITICAL | Missing nonce or chain ID in signed data |
| ETH-040 | Front-running | HIGH | Sensitive operation without commit-reveal |

### Token Issues (ETH-041 to ETH-048)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-041 | ERC-20 Non-standard Return | HIGH | Direct `transfer()` without SafeERC20 |
| ETH-042 | Fee-on-Transfer Incompatibility | HIGH | Balance check before/after transfer mismatch |
| ETH-043 | Rebasing Token Incompatibility | HIGH | Cached balance for rebasing tokens |
| ETH-044 | ERC-777 Reentrancy Hook | CRITICAL | Token callback without reentrancy guard |
| ETH-045 | Missing Zero Address Check | MEDIUM | Constructor/setter without `!= address(0)` |
| ETH-046 | Approval Race Condition | MEDIUM | `approve()` without prior zero-set |
| ETH-047 | Infinite Approval | LOW | `approve(spender, type(uint256).max)` |
| ETH-048 | Token Supply Manipulation | HIGH | Unrestricted mint/burn functions |

### Proxy & Upgrade (ETH-049 to ETH-054)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-049 | Uninitialized Implementation | CRITICAL | `Initializable` without `_disableInitializers()` |
| ETH-050 | Storage Layout Mismatch | CRITICAL | New variables inserted before existing ones |
| ETH-051 | Function Selector Clash | HIGH | 4-byte selector collision between functions |
| ETH-052 | Missing Upgrade Authorization | CRITICAL | `upgradeTo` without access control |
| ETH-053 | selfdestruct in Implementation | HIGH | Implementation can be destroyed |
| ETH-054 | Transparent Proxy Collision | HIGH | Admin function selector matches implementation |

### DeFi Specific (ETH-055 to ETH-065)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-055 | Governance Manipulation | HIGH | Low quorum or flash-loan-votable tokens |
| ETH-056 | Liquidation Manipulation | HIGH | Liquidation parameters exploitable |
| ETH-057 | Vault Share Inflation | CRITICAL | First depositor can inflate share price |
| ETH-058 | Donation Attack | HIGH | Direct token transfer manipulates accounting |
| ETH-059 | AMM Constant Product Error | CRITICAL | Incorrect k calculation in swap |
| ETH-060 | Missing Transaction Deadline | MEDIUM | Swap without deadline parameter |
| ETH-061 | Unrestricted Flash Mint | HIGH | Flash loan without fee or limit |
| ETH-062 | Pool Imbalance Attack | HIGH | Single-sided liquidity manipulation |
| ETH-063 | Reward Distribution Error | HIGH | Incorrect reward calculation per share |
| ETH-064 | Insecure Callback Handler | HIGH | Hook/callback without validation |
| ETH-065 | Cross-protocol Integration Risk | MEDIUM | External protocol call without validation |

### Gas & DoS (ETH-066 to ETH-070)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-066 | Unbounded Loop | HIGH | Loop over dynamic array without gas bound |
| ETH-067 | Block Gas Limit DoS | HIGH | Transaction exceeds block gas limit |
| ETH-068 | Unexpected Revert in Loop | MEDIUM | Single revert blocks entire batch |
| ETH-069 | Griefing Attack | MEDIUM | Attacker can waste victim's gas |
| ETH-070 | Storage Slot Exhaustion | LOW | Unbounded mapping/array growth |

### Miscellaneous (ETH-071 to ETH-080)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-071 | Floating Pragma | LOW | `pragma solidity ^X.Y.Z` |
| ETH-072 | Outdated Compiler | LOW | Solidity version < 0.8.20 |
| ETH-073 | Hash Collision (encodePacked) | MEDIUM | `abi.encodePacked` with dynamic types |
| ETH-074 | Right-to-Left Override | HIGH | Unicode override character in source |
| ETH-075 | Code With No Effects | LOW | Statement without side effects |
| ETH-076 | Missing Event Emission | LOW | State change without event |
| ETH-077 | Incorrect Inheritance Order | MEDIUM | C3 linearization issue |
| ETH-078 | Private Data On-Chain | LOW | Sensitive data in storage |
| ETH-079 | Hardcoded Gas Amount | LOW | Fixed gas in `.call{gas: X}()` |
| ETH-080 | Incorrect Constructor (legacy) | HIGH | Misspelled constructor name (pre-0.4.22) |

### Transient Storage — EIP-1153 (ETH-081 to ETH-085)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-081 | Transient Storage Slot Collision | CRITICAL | Same TSTORE slot via delegatecall |
| ETH-082 | Transient Storage Not Cleared | HIGH | TSTORE value persists across calls |
| ETH-083 | TSTORE Reentrancy Bypass | CRITICAL | Transient lock bypassed cross-contract |
| ETH-084 | Transient Storage Delegatecall | HIGH | TSTORE exposed via delegatecall context |
| ETH-085 | Transient Storage Type-Safety | MEDIUM | Type confusion in transient slots |

### EIP-7702 / Pectra (ETH-086 to ETH-089)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-086 | Broken tx.origin == msg.sender | CRITICAL | EOA assumption broken by EIP-7702 |
| ETH-087 | Malicious EIP-7702 Delegation | HIGH | Delegated code execution |
| ETH-088 | Cross-Chain Auth Replay | CRITICAL | Authorization without chain ID binding |
| ETH-089 | EOA Code Assumption | HIGH | `extcodesize == 0` check unreliable |

### Account Abstraction — ERC-4337 (ETH-090 to ETH-093)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-090 | UserOp Hash Collision | HIGH | Weak UserOperation hashing |
| ETH-091 | Paymaster Exploitation | CRITICAL | Paymaster without spend limits |
| ETH-092 | Bundler Manipulation | HIGH | Bundler can reorder/censor operations |
| ETH-093 | Validation-Execution Confusion | CRITICAL | Side effects in validation phase |

### Modern DeFi (ETH-094 to ETH-097)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-094 | Uniswap V4 Hook Auth Bypass | CRITICAL | Hook callback without PoolManager check |
| ETH-095 | Hook Data Manipulation | HIGH | Unvalidated hookData parameter |
| ETH-096 | Cached State Desynchronization | HIGH | Stale cached values after external interaction |
| ETH-097 | Known Compiler Bug | HIGH | Solidity version with known bugs |

### Input Validation (ETH-098 to ETH-099)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-098 | Missing Boundary Check | HIGH | No validation on numeric parameters |
| ETH-099 | Unsafe ABI Decoding | HIGH | `abi.decode` without length check |

### Off-Chain & Infrastructure (ETH-100 to ETH-101)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-100 | EIP-7702 Delegation Phishing | CRITICAL | Social engineering delegation approval |
| ETH-101 | Off-Chain Infrastructure Compromise | CRITICAL | Frontend/signer/multisig compromise |

### Restaking & L2 (ETH-102 to ETH-104)

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| ETH-102 | Cascading Slashing Risk | HIGH | Restaking without slashing isolation |
| ETH-103 | L2 Sequencer Dependency | HIGH | No sequencer uptime check |
| ETH-104 | L2 Message Replay | CRITICAL | Cross-domain message without replay protection |
