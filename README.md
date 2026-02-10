<p align="center">
  <img src="https://img.shields.io/badge/Patterns-104-blue?style=flat-square" alt="104 Patterns" />
  <img src="https://img.shields.io/badge/Tools-8-blue?style=flat-square" alt="8 Tools" />
  <img src="https://img.shields.io/badge/DeFiVulnLabs-100%25-brightgreen?style=flat-square" alt="DeFiVulnLabs 100%" />
  <img src="https://img.shields.io/badge/Paradigm%20CTF-100%25-brightgreen?style=flat-square" alt="Paradigm CTF 100%" />
  <img src="https://img.shields.io/badge/Tests-66-brightgreen?style=flat-square" alt="66 Tests" />
  <img src="https://img.shields.io/badge/OWASP%202025-Aligned-orange?style=flat-square" alt="OWASP 2025" />
  <img src="https://img.shields.io/badge/License-Non--Commercial-lightgrey?style=flat-square" alt="License" />
</p>

# SolidityGuard

Advanced AI-powered Solidity/EVM smart contract security audit agent.

> **Try it now at [solidityguard.org](https://solidityguard.org)** — no setup required. Upload your contracts and get a comprehensive security analysis in minutes.

> **Need a professional audit?** Contact **maintainers@altresear.ch** for comprehensive manual + AI-assisted security reviews.

---

## Features

- **104 Vulnerability Patterns** (ETH-001 to ETH-104) — reentrancy, access control, DeFi, proxy, oracle, transient storage, EIP-7702, ERC-4337, restaking, L2
- **8-Tool Integration** — Slither, Mythril, Echidna, Aderyn, Foundry v1.0, Medusa v1, Halmos, Certora
- **Multi-Agent Architecture** — 9 specialized sub-agents for deep parallel analysis
- **7-Phase Deep Audit** — scan, verify, parallel agents, exploit PoC, dynamic verification, fuzz, report
- **Dynamic Exploit Verification** — Foundry fork-based PoC testing on forked mainnet
- **Formal Verification** — Halmos symbolic tests + Certora CVL rules
- **Professional Reports** — OpenZeppelin/Trail of Bits-style Markdown + PDF with severity scoring
- **Cross-Tool Verification** — confidence boosting, deduplication, false positive reduction
- **Fuzz Test Generation** — Foundry invariant tests + Echidna property tests from scan findings
- **OWASP 2025 Aligned** — covers all Smart Contract Top 10 2025 categories
- **CTF-Validated** — 100% detection on DeFiVulnLabs (56/56) + Paradigm CTF (24/24 static)
- **3 Surfaces** — CLI (Click + Rich), Web (FastAPI + React + WebSocket), Desktop (Tauri v2)

## Benchmark Results

| Benchmark | Scope | Detection Rate |
|-----------|-------|----------------|
| **DeFiVulnLabs** | 56 contracts, 59 patterns | **100%** (56/56) |
| **Paradigm CTF 2021** | 16 challenges | **100%** (10/10 static) |
| **Paradigm CTF 2022** | 13 challenges | **100%** (7/7 static) |
| **Paradigm CTF 2023** | 15 challenges | **100%** (7/7 static) |
| **Combined** | 100 contracts | **80/80 static (100%)** |

```bash
python3 scripts/ctf_benchmark.py --all    # Run all benchmarks
python3 -m pytest scripts/test_scanners.py -v  # 43 scanner tests
```

---

## Quick Start

### Docker (Recommended)

```bash
# CLI audit
docker build -t solidityguard .
docker run -v ./contracts:/audit solidityguard audit /audit

# Web UI at http://localhost:8000
docker compose up
```

### CLI

```bash
cd apps/cli && pip install -e .

solidityguard audit ./contracts           # Full audit
solidityguard audit --quick ./contracts   # Pattern-only scan
solidityguard scan ./contracts --category reentrancy
solidityguard report findings.json -o report.md
solidityguard patterns                    # List all 104 patterns
solidityguard tools                       # Check installed tools
```

### Web

```bash
# Backend
cd apps/web/backend && pip install -e .
uvicorn solidityguard_api.main:app --reload

# Frontend (separate terminal)
cd apps/web/frontend && npm install && npm run dev
```

### Desktop (Tauri v2)

```bash
cd apps/desktop && npm install && npm run tauri dev
```

Desktop app scans contracts locally using installed tools (slither, aderyn) or Docker as fallback — no backend server required.

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
│  Foundry v1.0 │ Halmos │ Certora │ Report Gen.  │
└──────────────────────────────────────────────────┘
```

## Tool Integration

| Tool | Type | Speed | Detectors |
|------|------|-------|-----------|
| **Slither** | Static analysis | < 1 sec | 90+ built-in |
| **Aderyn** | Static analysis (Rust) | Sub-second | 100+ detectors |
| **Mythril** | Symbolic execution | Minutes | Deep path analysis |
| **Echidna** | Property-based fuzzing | 3K+ tx/sec | Custom invariants |
| **Medusa v1** | Coverage-guided fuzzing | Parallel | Trail of Bits |
| **Foundry v1.0** | Test + fuzz + fork | Fast | Invariant tests |
| **Halmos** | Formal verification | Minutes | a16z symbolic testing |
| **Certora** | Formal verification | Minutes | CVL rules |

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
├── docker/                     # Docker configs
├── Dockerfile                  # CLI Docker image
├── docker-compose.yml          # Web + CLI orchestration
└── .github/workflows/          # CI/CD
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Add vulnerability patterns, improve detection rules, or reduce false positives
4. Ensure all tests pass: `python3 -m pytest scripts/test_scanners.py -v`
5. Submit a Pull Request

Contributions welcome in these areas:
- New vulnerability pattern detectors
- Exploit case studies (anonymized)
- Tool integrations
- False positive reduction
- Documentation improvements

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

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND.**

SolidityGuard is an automated security analysis tool and is **not a substitute for a professional manual security audit**. No automated tool can guarantee detection of all vulnerabilities. Use at your own risk.

**Limitation of liability:** To the maximum extent permitted by law, Alt Research Ltd. shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising from use of this software.

**Indemnification:** By using SolidityGuard, you agree to indemnify and hold harmless Alt Research Ltd. from any claims arising from your use of the software.

For a professional manual audit, contact **maintainers@altresear.ch**.

See full terms at [solidityguard.org/terms](https://solidityguard.org/terms) and [solidityguard.org/privacy](https://solidityguard.org/privacy).

## Donate

If you find SolidityGuard useful:

**EVM (Ethereum / Base / Arbitrum):** `0x03978ef315341ed6501c9a571e36695905a0b931`

## License

Copyright Alt Research Ltd. 2026. All rights reserved. See [LICENSE](LICENSE) for details.
