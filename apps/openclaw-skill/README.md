# SolidityGuard — OpenClaw Skill

Advanced Solidity/EVM smart contract security audit skill for [OpenClaw](https://openclaw.ai).

## Features

- **104 vulnerability patterns** (ETH-001 to ETH-104)
- **50+ pattern detectors** covering reentrancy, access control, DeFi, proxy, oracle, and more
- **100% detection rate** on DeFiVulnLabs (56/56) + Paradigm CTF (24/24 static)
- **8-tool integration** — Slither, Aderyn, Mythril, Foundry, Echidna, Medusa, Halmos, Certora
- **Professional reports** — OpenZeppelin/Trail of Bits style Markdown + PDF
- **OWASP 2025 aligned** — covers all Smart Contract Top 10 categories

## Install

### Via ClawHub

```bash
npx clawhub@latest install solidityguard
```

### Manual

Copy this directory to your OpenClaw skills folder:

```bash
cp -r . ~/.openclaw/skills/solidityguard/
```

Or for workspace-local installation:

```bash
cp -r . ./skills/solidityguard/
```

## Usage

Once installed, just ask your OpenClaw agent:

- "Audit my contracts for security vulnerabilities"
- "Scan this DeFi protocol for reentrancy"
- "Check for flash loan attack vectors"
- "Generate a security report for my contracts"
- "Write fuzz tests for this vault contract"

## Requirements

- Python 3.10+
- Optional: Slither, Aderyn, Mythril, Foundry (for full scan capabilities)

## Structure

```
solidityguard/
├── SKILL.md              # OpenClaw skill definition
├── README.md             # This file
├── scripts/
│   ├── scan.sh           # Scanner wrapper
│   ├── report.sh         # Report generator wrapper
│   ├── install.sh        # Dependency installer
│   ├── solidity_guard.py # Core scanner (50+ detectors)
│   └── report_generator.py # Report generator
└── references/
    ├── patterns.md       # 104 vulnerability patterns reference
    └── exploits.md       # Notable 2025-2026 exploit case studies
```

## License

MIT
