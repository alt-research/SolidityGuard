---
name: solidity-guard:report
description: Generate a professional audit report from scan results or contracts
argument-hint: "[path-or-json]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Write
  - Task
---

# Generate Professional Audit Report

Generate a professional-grade security audit report following industry standards (OpenZeppelin, Trail of Bits, Cyfrin format).

## Quick Start

```bash
# Generate report from Slither results
python3 .claude/skills/solidity-guard/scripts/report_generator.py slither-results.json --output report.md

# Generate both Markdown and PDF
python3 .claude/skills/solidity-guard/scripts/report_generator.py slither-results.json --output report.md --pdf

# With project and client name
python3 .claude/skills/solidity-guard/scripts/report_generator.py slither-results.json --output report.md --project "DeFi Protocol" --client "Acme Corp"
```

## Report Structure (OpenZeppelin/ToB Style)

1. **Executive Overview**
   - Introduction to the engagement
   - Assessment summary with severity counts
   - Overall risk level and security score (0-100)
   - Test approach & methodology

2. **Risk Methodology**
   - Severity classification (Critical > High > Medium > Low > Informational)
   - Likelihood × Impact matrix
   - Confidence scoring

3. **Findings Overview**
   - Summary table by severity
   - Complete findings list with locations

4. **Detailed Findings**
   - Each finding includes:
     - Description
     - Code location (file:line)
     - Code evidence (snippet)
     - Impact assessment
     - Recommendation
     - Remediation status

5. **Tool Analysis**
   - Slither results summary
   - Aderyn results summary
   - Mythril results summary
   - Coverage metrics

## Security Score Calculation

```
Score = 100 - (Critical × 15) - (High × 8) - (Medium × 3) - (Low × 1)
Score = max(0, Score)
```

- 100: No vulnerabilities found
- 80-99: Minor issues, production-ready with fixes
- 50-79: Significant issues, major remediation needed
- 0-49: Critical vulnerabilities, do not deploy

## Output Formats
- **Markdown (.md)** - Human-readable, GitHub-compatible
- **PDF** - Professional document for stakeholders
- **JSON** - Structured data for CI/CD integration
