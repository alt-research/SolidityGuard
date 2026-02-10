# Proxy & Upgradeable Contract Security Checklist

## Implementation Contract
- [ ] `_disableInitializers()` called in constructor
- [ ] Or `initializer` modifier on `initialize()` function
- [ ] No `selfdestruct` or `delegatecall` in implementation
- [ ] No immutable state that conflicts with proxy storage

## Storage Layout
- [ ] Variables only appended, never reordered between versions
- [ ] No variable type changes between versions
- [ ] Storage gaps (`uint256[50] __gap`) in all base contracts
- [ ] `forge inspect` storage layout compared between versions
- [ ] Inherited contract order consistent

## UUPS Pattern
- [ ] `_authorizeUpgrade()` has proper access control (onlyOwner/onlyRole)
- [ ] Implementation has UUPSUpgradeable inherited
- [ ] No way to brick upgrade by deploying bad implementation

## Transparent Proxy
- [ ] Admin cannot call implementation functions (proxy handles)
- [ ] No function selector collisions between proxy and impl
- [ ] ProxyAdmin contract properly configured

## Beacon Proxy
- [ ] Beacon owner properly secured
- [ ] All proxies update atomically with beacon

## Initialization
- [ ] All state properly initialized in `initialize()`
- [ ] No constructor state relied upon
- [ ] `initializer` modifier prevents double-init
- [ ] Child contracts call parent `__ContractName_init()`

## ERC-7201 (Namespaced Storage)
- [ ] Storage struct uses keccak256 namespaced slot
- [ ] No conflicts with standard proxy storage slots
- [ ] All upgradeable state in namespaced structs
