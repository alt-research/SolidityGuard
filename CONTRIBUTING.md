# Contributing to SolidityGuard

Thank you for your interest in contributing to SolidityGuard! This guide will help you get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/alt-research/SolidityGuard.git
cd SolidityGuard

# Run scanner tests
python3 -m pytest .claude/skills/solidity-guard/scripts/test_scanners.py -v

# Run CTF benchmarks
python3 .claude/skills/solidity-guard/scripts/ctf_benchmark.py --all

# Frontend
cd apps/web/frontend && npm install && npm run dev

# Backend
cd apps/web/backend && pip install -e . && uvicorn solidityguard_api.main:app --reload

# Desktop
cd apps/desktop && npm install && npm run tauri dev
```

## How to Contribute

### New Vulnerability Pattern Detectors

1. Add the detector in `.claude/skills/solidity-guard/scripts/solidity_guard.py` inside `scan_patterns()`
2. Add a test case in `test_scanners.py`
3. Verify it passes: `python3 -m pytest test_scanners.py -v`
4. Run the CTF benchmark to ensure no regressions: `python3 ctf_benchmark.py --all`

### Exploit Case Studies

Add to `knowledge-base/exploits/` with the format:

```markdown
# Incident Name ($XXM Loss)

## Summary
Brief description.

## Root Cause
ETH-XXX: Pattern name

## Attack Steps
1. Step one
2. Step two

## Remediation
How to prevent this.
```

### False Positive Reduction

If you find a false positive in the scanner:

1. Create a minimal `.sol` file that triggers the false positive
2. Add a test case showing the expected behavior
3. Fix the detector logic
4. Verify the CTF benchmark still passes at 100%

### Tool Integrations

We integrate with Slither, Aderyn, Mythril, Echidna, Medusa, Foundry, Halmos, and Certora. To improve an integration:

1. Check the relevant runner in `.claude/skills/solidity-guard/scripts/`
2. Test with real contracts
3. Ensure finding deduplication works across tools

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes
4. Ensure all tests pass:
   ```bash
   python3 -m pytest .claude/skills/solidity-guard/scripts/test_scanners.py -v
   python3 -m pytest apps/web/backend/ -v
   cd apps/web/frontend && npx tsc --noEmit
   ```
5. Submit a PR with a clear description

## Code Style

- **Python**: Follow existing style, use type hints where practical
- **TypeScript/React**: Follow existing patterns, Tailwind for styling
- **Rust**: Standard Rust formatting (`cargo fmt`)
- **Commit messages**: Concise, imperative mood (e.g., "Add ETH-105 pattern detector")

## Areas for Contribution

- New vulnerability pattern detectors (ETH-105+)
- Exploit case studies (anonymized)
- Tool integrations and runner improvements
- False positive reduction
- Documentation improvements
- Frontend UI/UX improvements
- Desktop app features

## Questions?

Open an issue or reach out at **maintainers@altresear.ch**.
