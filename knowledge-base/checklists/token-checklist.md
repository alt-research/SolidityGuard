# Token Security Checklist (ERC-20/721/1155)

## ERC-20
- [ ] Uses SafeERC20 for external token interactions
- [ ] Handles non-standard return values (USDT, BNB)
- [ ] Fee-on-transfer tokens accounted for (check balance diff)
- [ ] Rebasing tokens handled (elastic supply)
- [ ] Zero-address checks on transfer/approve
- [ ] Approval race condition mitigated (approve 0 then N)
- [ ] No infinite approval assumed safe
- [ ] Decimals handled correctly (6, 8, 18 variations)
- [ ] Token blacklist/pause features won't break protocol
- [ ] ERC-777 hooks don't cause reentrancy

## ERC-721
- [ ] `onERC721Received` callback doesn't cause reentrancy
- [ ] Token IDs validated (no overflow/underflow)
- [ ] Metadata URI can't be manipulated
- [ ] Transfer hooks don't allow arbitrary execution
- [ ] Enumerable gas costs considered for large collections

## ERC-1155
- [ ] Batch operations gas-bounded
- [ ] `onERC1155Received` / `onERC1155BatchReceived` safe from reentrancy
- [ ] Supply tracking correct for fungible/non-fungible
- [ ] URI substitution secure

## General Token Safety
- [ ] Minting restricted to authorized roles
- [ ] Burning can't be used to grief other users
- [ ] Total supply invariants maintained
- [ ] Snapshot mechanism manipulation-resistant
- [ ] Flash minting (if supported) doesn't break invariants
