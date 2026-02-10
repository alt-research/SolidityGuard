# SolidityGuard CLI

AI-powered Solidity smart contract security audit command-line tool with rich terminal UI.

## Install

```bash
cd apps/cli
pip install -e .
```

## Usage

```bash
# Full audit
solidityguard audit ./contracts
solidityguard audit ./contracts --quick    # pattern scanner only
solidityguard audit ./contracts -o findings.json

# Targeted scan
solidityguard scan ./contracts                        # all patterns
solidityguard scan ./contracts --category reentrancy  # by category
solidityguard scan ./contracts --pattern ETH-001      # specific pattern

# Report generation
solidityguard report findings.json --format markdown
solidityguard report findings.json --format pdf

# Benchmark
solidityguard benchmark              # DeFiVulnLabs
solidityguard benchmark --paradigm   # Paradigm CTF
solidityguard benchmark --all        # combined

# Info
solidityguard patterns                    # list all 104 patterns
solidityguard patterns --category defi    # filter by category
solidityguard tools                       # check tool availability
solidityguard version                     # version info
```

## Running as Module

```bash
python -m solidityguard version
python -m solidityguard audit ./contracts
```
