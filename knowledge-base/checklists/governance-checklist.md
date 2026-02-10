# Governance Security Checklist

## Voting Mechanism
- [ ] Voting power based on snapshots (not current balance)
- [ ] Flash loan resistant (ERC20Votes with checkpoints)
- [ ] No double-voting across positions/tokens
- [ ] Delegation secure and tracked
- [ ] Vote weight calculation overflow-safe

## Proposal Lifecycle
- [ ] Minimum proposal threshold prevents spam
- [ ] Voting period adequate (2-7 days)
- [ ] Quorum based on past supply snapshot
- [ ] Execution timelock (24-48 hours minimum)
- [ ] Proposal can't be executed twice

## Safety Mechanisms
- [ ] Guardian/veto role for emergencies
- [ ] Cancel mechanism for malicious proposals
- [ ] Timelock admin can't bypass governance
- [ ] Emergency pause doesn't require governance

## Anti-manipulation
- [ ] Proposal creation requires non-trivial token holding
- [ ] No way to change vote after casting
- [ ] Quorum can't be met with flash-borrowed tokens
- [ ] Execution delay allows community review
