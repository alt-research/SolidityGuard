# General Solidity Security Checklist

## Access Control
- [ ] All state-changing functions have appropriate access control
- [ ] No use of `tx.origin` for authentication
- [ ] `msg.sender` used consistently for authorization
- [ ] Ownership transfer uses two-step pattern (Ownable2Step)
- [ ] Critical operations behind timelock
- [ ] Admin keys use multisig wallet

## Reentrancy
- [ ] Checks-Effects-Interactions (CEI) pattern followed everywhere
- [ ] `nonReentrant` modifier on all functions with external calls
- [ ] No cross-function reentrancy via shared state
- [ ] ERC-777 token hooks handled safely
- [ ] Flash loan callbacks follow CEI

## Arithmetic
- [ ] Solidity 0.8+ used (built-in overflow protection)
- [ ] `unchecked` blocks reviewed for overflow safety
- [ ] No division before multiplication
- [ ] Rounding direction favors protocol (round down for user claims)
- [ ] Precision loss acceptable in all calculations

## External Calls
- [ ] All `.call()` return values checked
- [ ] No `delegatecall` to untrusted addresses
- [ ] SafeERC20 used for all token transfers
- [ ] Low-level calls avoided where possible
- [ ] Gas stipend considered for `.call{}`

## Oracle & Price
- [ ] TWAP or multiple oracle sources used
- [ ] Oracle staleness checked (`updatedAt` validated)
- [ ] Price deviation bounds enforced
- [ ] Flash loan manipulation resistant

## Proxy & Upgrades
- [ ] Implementation contract initialized or `_disableInitializers()` in constructor
- [ ] Storage layout consistent between versions (append-only)
- [ ] Storage gaps (`__gap`) in base contracts
- [ ] `_authorizeUpgrade` properly protected (UUPS)
- [ ] No `selfdestruct` in implementation

## Token Integration
- [ ] SafeERC20 for all ERC-20 interactions
- [ ] Fee-on-transfer tokens handled
- [ ] Rebasing tokens handled (if supported)
- [ ] Zero-address checks on token parameters
- [ ] Approval race condition mitigated (approve 0 first)

## General
- [ ] Pragma locked to specific version
- [ ] Latest stable Solidity compiler used
- [ ] No floating pragma in production
- [ ] Events emitted for all state changes
- [ ] NatSpec documentation complete
- [ ] Comprehensive test suite with edge cases
- [ ] Invariant/fuzz tests for critical paths
