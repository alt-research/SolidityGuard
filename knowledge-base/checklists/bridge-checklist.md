# Cross-Chain Bridge Security Checklist

## Message Verification
- [ ] All messages cryptographically verified
- [ ] Signature scheme secure (no malleability)
- [ ] Validator set changes properly authorized
- [ ] Quorum threshold adequate (>= 2/3)
- [ ] No single point of failure in verification

## Replay Protection
- [ ] Nonce or message hash tracked
- [ ] Cross-chain replay prevented (chain ID in message)
- [ ] Same-chain replay prevented (nonce increment)
- [ ] Used nonces can't be reused after upgrade

## Fund Security
- [ ] Rate limiting on large transfers
- [ ] Maximum transfer limits per period
- [ ] Emergency pause mechanism
- [ ] Fund recovery mechanism exists
- [ ] Lock-mint / burn-unlock properly balanced

## Validator/Relayer
- [ ] Validator set management secured by governance
- [ ] Relayer validation prevents censorship
- [ ] Offline validator handling
- [ ] Validator rotation doesn't break in-flight messages
- [ ] Slashing for malicious validators

## Token Mapping
- [ ] Correct token decimals across chains
- [ ] Token address mapping verified
- [ ] Wrapped token supply <= locked tokens
- [ ] No minting without corresponding lock
