---
name: report-generator
description: |
  Generates professional security audit reports from findings. Creates OpenZeppelin/Trail of Bits
  style reports with executive summary, methodology, severity-classified findings, and
  remediation recommendations.
allowed-tools:
  - Read
  - Write
  - Grep
  - Glob
---

# Security Audit Report Generator

## 1. Purpose

Transform raw security findings into professional, actionable audit reports following industry standards from OpenZeppelin, Trail of Bits, and Cyfrin.

## 2. Severity Classification

### CRITICAL
- Direct loss of funds possible
- Complete protocol takeover
- No user interaction required
- Exploitable in single transaction
- **Examples**: Reentrancy drain, missing access control on withdraw, oracle manipulation

### HIGH
- Significant fund loss with conditions
- Privilege escalation
- State corruption affecting multiple users
- **Examples**: Cross-function reentrancy, integer overflow, delegatecall to untrusted

### MEDIUM
- Limited fund loss or DoS
- Governance manipulation
- Requires specific conditions
- **Examples**: Rounding errors, timestamp dependence, centralization risk

### LOW
- Minor issues, best practice violations
- Theoretical attacks with high cost
- **Examples**: Missing events, gas inefficiency, floating pragma

### INFORMATIONAL
- Code quality, documentation
- Non-security improvements
- **Examples**: Unused variables, naming conventions, missing NatSpec

## 3. Report Structure

```markdown
# Security Audit Report
## [Protocol Name]

**Prepared by**: SolidityGuard AI Security Audit Agent
**Date**: [YYYY-MM-DD]

## 1. Executive Summary
[Overview, scope, key findings, deployment recommendation]

## 2. Scope & Methodology
[Files reviewed, tools used, commit hash, limitations]

## 3. Findings Overview
| Severity | Count | Fixed | Open |
|----------|-------|-------|------|
| Critical | X | X | X |
| High | X | X | X |
| Medium | X | X | X |
| Low | X | X | X |
| Info | X | - | - |

## 4. Detailed Findings
### 4.1 Critical
[Each finding with description, evidence, impact, PoC, recommendation]

### 4.2 High
[...]

## 5. Recommendations
### Immediate (Pre-deployment)
### Short-term (30 days)
### Long-term (Ongoing)

## 6. Appendix
### A. File Listing
### B. Tool Versions
### C. Glossary
```

## 4. Finding Template

```markdown
## [CRITICAL] SG-001: Reentrancy in withdraw()

**Location**: `contracts/Vault.sol:45`
**Pattern**: ETH-001 (SWC-107)
**Status**: Open

### Description
The withdraw function sends ETH before updating the user's balance,
allowing an attacker to re-enter and drain the contract.

### Impact
Complete loss of all vault funds.

### Proof of Concept
```solidity
contract Attacker {
    Vault target;
    function attack() external payable {
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}
```

### Recommendation
```solidity
function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```
```

## 5. Security Score

```
Score = 100 - (Critical × 15) - (High × 8) - (Medium × 3) - (Low × 1)
```

| Score | Risk | Recommendation |
|-------|------|----------------|
| 90-100 | Minimal | Deploy with monitoring |
| 70-89 | Low | Fix findings, re-review |
| 50-69 | Medium | Major remediation required |
| 25-49 | High | Critical remediation |
| 0-24 | Critical | Do NOT deploy |

## 6. Quality Checklist

- [ ] All findings have exact file:line locations
- [ ] Code snippets are accurate and from source
- [ ] Severity classifications are justified
- [ ] Attack scenarios are realistic and specific
- [ ] Recommendations are actionable with code
- [ ] No speculation or hallucination
- [ ] Executive summary matches detailed findings
- [ ] Metrics are accurate
