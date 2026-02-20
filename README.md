<h1 align="center">SolidityGuard</h1>

<p align="center">
  <strong>Advanced Solidity/EVM smart contract security auditor</strong>
</p>

<p align="center">
  <a href="https://github.com/alt-research/SolidityGuard/actions/workflows/ci.yml"><img src="https://github.com/alt-research/SolidityGuard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/alt-research/SolidityGuard/releases/latest"><img src="https://img.shields.io/github/v/release/alt-research/SolidityGuard?color=%234f46e5" alt="Latest Release" /></a>
  <a href="https://solidityguard.org"><img src="https://img.shields.io/badge/Web-solidityguard.org-green" alt="Web App" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Proprietary-red" alt="License" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Patterns-104-blue?style=flat-square" alt="104 Patterns" />
  <img src="https://img.shields.io/badge/Tools-9-blue?style=flat-square" alt="9 Tools" />
  <img src="https://img.shields.io/badge/CTF%20Benchmark-85%2F85%20(100%25)-brightgreen?style=flat-square" alt="CTF 85/85 100%" />
  <img src="https://img.shields.io/badge/DeFiVulnLabs-56%2F56-brightgreen?style=flat-square" alt="DeFiVulnLabs 100%" />
  <img src="https://img.shields.io/badge/Paradigm%20CTF-24%2F24-brightgreen?style=flat-square" alt="Paradigm CTF 100%" />
  <img src="https://img.shields.io/badge/2025%20CTFs-5%2F5-brightgreen?style=flat-square" alt="2025 CTFs 100%" />
  <img src="https://img.shields.io/badge/EVMBench-120%2F120%20(100%25)-brightgreen?style=flat-square" alt="EVMBench 120/120" />
  <img src="https://img.shields.io/badge/OWASP%202025-Aligned-orange?style=flat-square" alt="OWASP 2025" />
</p>

<p align="center">
  <a href="https://solidityguard.org">Try it now</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#vulnerability-patterns-104">104 Patterns</a> &middot;
  <a href="https://github.com/alt-research/SolidityGuard/releases">Downloads</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

> **Try it now at [solidityguard.org](https://solidityguard.org)** — scan your Solidity contracts instantly from your browser, no installation required.

> **Need a professional, in-depth audit for your protocol?** Contact us at **maintainers@altresear.ch** — we offer comprehensive manual + AI-assisted security reviews tailored to your codebase.

## Features

- **104 Vulnerability Patterns** (ETH-001 to ETH-104) — from real audits, exploits, SWC Registry, OWASP 2025, and 2025-2026 research
- **9-Tool Integration** — Slither, Mythril, Echidna, Aderyn, Foundry v1.0, Medusa v1, Halmos, Certora, EVMBench
- **3 Application Surfaces** — CLI, Web ([solidityguard.org](https://solidityguard.org)), Desktop (Tauri v2)
- **Docker Support** — scan locally with zero setup, your code never leaves your machine
- **Professional Reports** — OpenZeppelin/Trail of Bits-style Markdown + PDF with severity scoring
- **7-Phase Deep Audit** — scan, verify, parallel agents, exploit PoC, dynamic verification, fuzz, report
- **Multi-Agent Architecture** — 9 specialized sub-agents for deep parallel analysis
- **Dynamic Exploit Verification** — Foundry fork-based PoC testing on forked mainnet
- **Formal Verification** — Halmos symbolic tests + Certora CVL rules
- **Fuzz Test Generation** — Foundry invariant tests + Echidna property tests from scan findings
- **OWASP 2025 Aligned** — covers all Smart Contract Top 10 2025 categories
- **CTF-Validated** — 100% detection on 85/85 challenges: DeFiVulnLabs (56/56) + Paradigm CTF (24/24) + R3CTF 2025 + HTB CA 2025 (5/5)
- **EVMBench Validated** — 120/120 (100%) ground-truth vulnerability coverage across 40 real-world audits

## Benchmark Results

| Benchmark | Scope | Detection Rate |
|-----------|-------|----------------|
| **DeFiVulnLabs** | 56 contracts, 59 patterns | **100%** (56/56) |
| **Paradigm CTF 2021** | 16 challenges | **100%** (10/10 static) |
| **Paradigm CTF 2022** | 13 challenges | **100%** (7/7 static) |
| **Paradigm CTF 2023** | 15 challenges | **100%** (7/7 static) |
| **R3CTF 2025** | 2 Solidity challenges | **100%** (2/2) |
| **HTB Cyber Apocalypse 2025** | 3 blockchain challenges | **100%** (3/3) |
| **Combined** | 85 challenges | **85/85 (100%)** |
| **EVMBench** | 40 audits, 120 vulnerabilities | **120/120 (100%)** |

### EVMBench Leaderboard

[EVMBench](https://github.com/openai/frontier-evals/tree/main/project/evmbench) (OpenAI, 2025) evaluates AI agents on real-world smart contract security across 40 audit codebases from Code4rena and Sherlock contests (120 high-severity vulnerabilities, 3 modes: Detect / Patch / Exploit).

SolidityGuard's pattern scanner achieves **100% ground-truth coverage** — detecting all 120 vulnerabilities across all 40 audits in 7.4 seconds. This scanner output is used as pre-scan input for the SolidityGuard agent.

**Vulnerability Detection — EVMBench Ground Truth (120 vulns, 40 audits)**

```
  SolidityGuard Scanner  ████████████████████████████████████████ 100.0%  (120/120)
  Claude Opus 4.6        █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  45.6%
  GPT-5.3-Codex          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  39.2%
  GPT-5.2 (Codex)        ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  39.2%
  Claude Opus 4.5        ███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  36.1%
  GPT-5.2 (OpenCode)     ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  30.0%
  GPT-5                  █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  23.3%
  Gemini 3 Pro           ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  20.8%
  o3                     ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  10.6%
```

**Full results** (from [EVMBench paper](https://github.com/openai/frontier-evals/tree/main/project/evmbench), Table 9):

| Model | Scaffold | Detect | Patch | Exploit |
|-------|----------|--------|-------|---------|
| **SolidityGuard** | **Claude Code** | **100.0%** * | — | — |
| Claude Opus 4.6 | Claude Code | 45.6% | 25.9% | 61.1% |
| GPT-5.3-Codex | Codex (xhigh) | 39.2% | **41.5%** | **72.2%** |
| GPT-5.2 | Codex (xhigh) | 39.2% | 39.3% | 62.5% |
| Claude Opus 4.5 | Claude Code | 36.1% | 21.5% | 50.9% |
| GPT-5.2 | OpenCode | 30.0% | 35.6% | 51.4% |
| GPT-5 | Codex | 23.3% | 20.0% | 31.9% |
| Gemini 3 Pro | Gemini CLI | 20.8% | 10.4% | 36.1% |
| o3 | Codex | 10.6% | 14.8% | 18.1% |

\* SolidityGuard Detect score is scanner-level ground-truth pattern coverage (120/120 vulns detected via static analysis). EVMBench agent Detect scores are from LLM-judged audit reports. SolidityGuard's scanner is used as a pre-scan input to boost the agent's audit coverage.

## Quick Start

### Web (Fastest)

Visit **[solidityguard.org](https://solidityguard.org)** to start scanning immediately — no setup needed.

### Docker (Recommended)

```bash
# Scan a local contracts directory (no Python needed)
docker build -t solidityguard .
docker run -v ./contracts:/audit solidityguard audit /audit

# Web UI — dashboard at http://localhost:8000
docker compose up
```

The desktop app auto-detects Docker and runs scans locally — your code never leaves your machine.

### CLI

```bash
cd apps/cli && pip install -e .

solidityguard audit ./contracts           # Full audit
solidityguard audit --quick ./contracts   # Pattern-only scan
solidityguard scan ./contracts --category reentrancy
solidityguard report findings.json -o report.md
solidityguard benchmark --all             # CTF benchmark (85/85)
solidityguard evmbench                    # EVMBench benchmark (120/120)
solidityguard evmbench --mode exploit     # EVMBench exploit mode
solidityguard patterns                    # List all 104 patterns
solidityguard tools                       # Check installed tools (9 tools)
```

### Desktop

Download from [Releases](https://github.com/alt-research/SolidityGuard/releases) — available for macOS (.dmg), Windows (.msi, .exe), and Linux (.AppImage, .deb).

Or build from source:

```bash
cd apps/desktop && npm install && npm run tauri dev
```

Desktop app scans contracts locally using installed tools (slither, aderyn) or Docker as fallback — no backend server required.

### Web (Self-Hosted)

```bash
# Backend
cd apps/web/backend && pip install -e .
uvicorn solidityguard_api.main:app --reload

# Frontend (separate terminal)
cd apps/web/frontend && npm install && npm run dev
# Open http://localhost:5173
```

### CI/CD Integration

Add SolidityGuard to your GitHub Actions workflow:

```yaml
- name: Run SolidityGuard
  run: |
    pip install slither-analyzer
    python3 scripts/solidity_guard.py scan --path ./contracts --json
    # Fail on critical findings
    CRITICAL=$(python3 -c "import json; d=json.load(open('results.json')); print(d.get('summary',{}).get('critical',0))")
    if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
```

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a complete example.

### Slash Commands (Claude Code Agent)

```bash
/audit ./contracts              # Full 7-phase audit
/deep-audit ./contracts         # Multi-agent parallel analysis
/scan-reentrancy ./contracts    # Focused reentrancy scan
/scan-access-control ./contracts
/report ./findings.json         # Generate professional report
/generate-fuzz ./contracts      # Generate fuzz tests
/verify-exploit ./results.json  # Dynamic exploit verification
```

---

## Vulnerability Patterns (104)

| Category | IDs | Count | Examples |
|----------|-----|-------|----------|
| Reentrancy | ETH-001–005 | 5 | Single, cross-function, cross-contract, read-only |
| Access Control | ETH-006–012 | 7 | Missing auth, tx.origin, unprotected selfdestruct |
| Arithmetic | ETH-013–017 | 5 | Overflow, precision loss, division ordering |
| External Calls | ETH-018–023 | 6 | Unchecked return, delegatecall, DoS |
| Oracle & Price | ETH-024–028 | 5 | Oracle manipulation, flash loans, MEV |
| Storage & State | ETH-029–033 | 5 | Uninitialized storage, proxy collision |
| Logic Errors | ETH-034–040 | 7 | Strict equality, timestamp, signatures, front-running |
| Token Issues | ETH-041–048 | 8 | Fee-on-transfer, rebasing, ERC-777 hooks |
| Proxy & Upgrade | ETH-049–054 | 6 | Uninitialized impl, storage mismatch, selector clash |
| DeFi Specific | ETH-055–065 | 11 | Governance, liquidation, vault inflation, AMM |
| Gas & DoS | ETH-066–070 | 5 | Unbounded loops, block gas limit |
| Miscellaneous | ETH-071–080 | 10 | Floating pragma, hash collision, compiler version |
| Transient Storage | ETH-081–085 | 5 | TSTORE collision, reentrancy bypass, delegatecall |
| EIP-7702 / Pectra | ETH-086–089 | 4 | tx.origin bypass, delegation, cross-chain replay |
| Account Abstraction | ETH-090–093 | 4 | UserOp collision, paymaster, bundler, validation |
| Modern DeFi | ETH-094–097 | 4 | Uniswap V4 hooks, cached state desync, compiler bugs |
| Input Validation | ETH-098–099 | 2 | Missing bounds checks, unsafe ABI decoding (OWASP #4) |
| Off-Chain & Infra | ETH-100–101 | 2 | EIP-7702 phishing, UI/signer compromise (Bybit-style) |
| Restaking & L2 | ETH-102–104 | 3 | Cascading slashing, sequencer deps, message replay |

## Architecture

```
┌──────────────────────────────────────────────────┐
│               ORCHESTRATION LAYER                │
│  Prompt Router │ Agent Scheduler │ Pattern Match  │
└──────────────────────────────────────────────────┘
                        │
┌──────────────────────────────────────────────────┐
│              AGENT LAYER (9 Skills)              │
│  Entry-Point   Vulnerability   Reentrancy Access │
│  Analyzer      Scanner         Auditor    Ctrl   │
│  Storage       DeFi           Spec     Fuzz      │
│  Analyzer      Analyzer       Compl.   Gen.      │
│  Report Generator                                │
└──────────────────────────────────────────────────┘
                        │
┌──────────────────────────────────────────────────┐
│              KNOWLEDGE LAYER                     │
│  104 Vuln Patterns │ 25+ Exploit Case Studies    │
│  SWC Registry │ Solodit DB │ Remediation Tmpl.   │
└──────────────────────────────────────────────────┘
                        │
┌──────────────────────────────────────────────────┐
│              TOOL LAYER                          │
│  Slither │ Mythril │ Aderyn │ Echidna │ Medusa   │
│  Foundry v1.0 │ Halmos │ Certora │ EVMBench     │
└──────────────────────────────────────────────────┘
```

## Tool Integration

| Tool | Type | Speed | Purpose |
|------|------|-------|---------|
| **Slither** | Static analysis | < 1 sec | 90+ built-in detectors |
| **Aderyn** | Static analysis (Rust) | Sub-second | 100+ detectors |
| **Mythril** | Symbolic execution | Minutes | Deep path analysis |
| **Echidna** | Property-based fuzzing | 3K+ tx/sec | Custom invariants |
| **Medusa v1** | Coverage-guided fuzzing | Parallel | Trail of Bits |
| **Foundry v1.0** | Test + fuzz + fork | Fast | Invariant tests |
| **Halmos** | Formal verification | Minutes | a16z symbolic testing |
| **Certora** | Formal verification | Minutes | CVL rules |
| **EVMBench** | Audit benchmark | Variable | 40 audits, 120 vulns |

## 7-Phase Deep Audit

```
Phase 1: Automated Scan       ─► Slither + Aderyn + Mythril + Medusa
Phase 2: Finding Verification  ─► Cross-reference tools, reduce FPs
Phase 3: Parallel Agents       ─► Reentrancy, Access, DeFi, Logic
Phase 4: Exploit PoC           ─► Attack scenarios + Foundry fork tests
Phase 5: Dynamic Verification  ─► Execute PoCs on forked mainnet
Phase 6: Fuzz Testing          ─► Foundry invariant + Echidna (3K+ tx/sec)
Phase 7: Report & Remediation  ─► Professional report + fixed code samples
```

## OWASP Smart Contract Top 10 (2025)

| Rank | Category | Coverage |
|------|----------|----------|
| #1 | Access Control ($953M in 2024) | ETH-006–012, ETH-049–054, ETH-086–093, ETH-100–101 |
| #2 | Oracle Manipulation | ETH-024–028, ETH-094–096 |
| #3 | Logic Errors | ETH-034–040, ETH-097 |
| #4 | Input Validation | ETH-098–099 |
| #5 | Reentrancy | ETH-001–005, ETH-044, ETH-081, ETH-083 |
| #6 | Unchecked Returns | ETH-018–023 |
| #7 | MEV / Front-running | ETH-026, ETH-040, ETH-060 |
| #8 | Arithmetic | ETH-013–017 |
| #9 | Unsafe Delegatecall | ETH-019, ETH-030, ETH-084 |
| #10 | Denial of Service | ETH-066–070 |

## Exploit Case Studies

| Incident | Loss | Root Cause | Pattern |
|----------|------|------------|---------|
| Bybit | $1.5B | Safe{Wallet} UI compromise | ETH-101 |
| Ronin Bridge | $625M | Missing access control | ETH-006 |
| BNB Bridge | $570M | Signature verification | ETH-038 |
| Wormhole | $326M | Missing validation | ETH-006 |
| Parity Wallet | $280M | Uninitialized proxy | ETH-049 |
| Euler Finance | $197M | Donation attack | ETH-058 |
| Nomad Bridge | $190M | Uninitialized storage | ETH-029 |
| Beanstalk | $182M | Flash loan governance | ETH-025, ETH-055 |
| Cream Finance | $130M | Oracle manipulation | ETH-024 |
| Balancer V2 | $128M | Read-only reentrancy | ETH-004 |
| Phemex | $73M | Hot wallet compromise | ETH-006 |
| UPCX | $70M | Unauthorized upgrade | ETH-052 |
| The DAO | $60M | Reentrancy | ETH-001 |
| GMX V1 | $42M | Oracle manipulation | ETH-024 |
| Meta Pool | $27M | Minting bug | ETH-048 |
| Cork Protocol | $11M | V4 hook auth bypass | ETH-094 |

## Scripts

| Script | Purpose |
|--------|---------|
| `solidity_guard.py` | Combined scanner orchestrator (50+ detectors) |
| `ctf_benchmark.py` | CTF benchmark framework (DeFiVulnLabs + Paradigm CTF + 2025 CTFs) |
| `slither_runner.py` | Slither integration |
| `report_generator.py` | Professional Markdown + PDF report |
| `verify_findings.py` | Finding verification prompts |
| `evmbench_local_benchmark.py` | EVMBench local benchmark (detect mode, 40 audits, 120 vulns) |
| `evmbench_runner.py` | EVMBench full runner (detect / exploit / patch via nanoeval) |
| `test_scanners.py` | Test suite (43 tests) |

All scripts are located in [`.claude/skills/solidity-guard/scripts/`](.claude/skills/solidity-guard/scripts/).

## Project Structure

```
SolidityGuard/
├── apps/
│   ├── cli/                    # Python CLI (Click + Rich)
│   ├── web/
│   │   ├── backend/            # FastAPI REST API + WebSocket
│   │   └── frontend/           # React 19 + Tailwind dark theme
│   ├── desktop/                # Tauri v2 (macOS/Linux/Windows)
│   └── openclaw-skill/         # OpenClaw AI agent skill
├── .claude/skills/solidity-guard/
│   ├── skills/                 # 9 specialized audit skills
│   ├── commands/               # 7 slash commands
│   └── scripts/                # Scanner, reporter, merger, verifier
├── knowledge-base/
│   ├── exploits/               # 25+ exploit case studies
│   └── checklists/             # 6 security checklists
├── .github/workflows/          # CI/CD
├── Dockerfile                  # CLI Docker image
└── docker-compose.yml          # Web + CLI orchestration
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Add vulnerability patterns, improve detection rules, or reduce false positives
4. Ensure all tests pass: `python3 -m pytest scripts/test_scanners.py -v`
5. Submit a Pull Request

Contributions welcome: new pattern detectors, exploit case studies, tool integrations, false positive reduction, and documentation.

## Security

Found a vulnerability in SolidityGuard itself? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## References

- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Trail of Bits Building Secure Contracts](https://secure-contracts.com/)
- [SWC Registry](https://swcregistry.io/)
- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
- [Solodit Vulnerability Database](https://solodit.xyz/)
- [Cyfrin Audit Checklist](https://github.com/Cyfrin/audit-checklist)
- [Nethermind Public Audit Reports](https://github.com/NethermindEth/PublicAuditReports)
- [Ethereum.org Smart Contract Security](https://ethereum.org/developers/docs/smart-contracts/security/)

## Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR IMPLIED.**

SolidityGuard is an automated security analysis tool and is **not a substitute for a comprehensive, professional manual security audit**. While SolidityGuard employs 104 vulnerability patterns and 8 security tools, **no automated tool can guarantee the detection of all vulnerabilities, bugs, or security issues** in smart contracts. New attack vectors, zero-day exploits, and novel vulnerability patterns may not be covered.

**Use at your own risk.** You are solely responsible for any decisions you make based on SolidityGuard's output, including deploying smart contracts, managing funds, or modifying code. The absence of findings does not certify a contract as secure.

**Limitation of liability:** To the maximum extent permitted by applicable law, Alt Research Ltd., its directors, officers, employees, agents, and affiliates shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of funds, tokens, digital assets, profits, revenue, or business opportunities arising from the use of this software or reliance on its output.

**Indemnification:** By using SolidityGuard, you agree to indemnify, defend, and hold harmless Alt Research Ltd. from any claims, liabilities, damages, losses, costs, and expenses arising from your use of the software, your smart contracts, or any reliance on the software's output.

For a professional manual audit, contact **maintainers@altresear.ch**.

See the full [LICENSE](LICENSE) for details.

## Donate

If you find SolidityGuard useful:

**EVM (Ethereum / Base / Arbitrum):** `0x03978ef315341ed6501c9a571e36695905a0b931`

## License

Copyright Alt Research Ltd. 2026. All rights reserved. See [LICENSE](LICENSE) for details.
