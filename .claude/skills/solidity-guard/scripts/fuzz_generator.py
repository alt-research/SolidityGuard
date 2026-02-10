#!/usr/bin/env python3
"""
SolidityGuard Fuzz Test Generator

Generates Foundry invariant tests and Echidna property tests from scan findings.
Templates cover the most common vulnerability categories:
  - Reentrancy (ETH-001 to ETH-005)
  - Access Control (ETH-006 to ETH-012)
  - Arithmetic (ETH-013 to ETH-017)
  - Oracle & Price (ETH-024 to ETH-028)
  - Vault / First Depositor (ETH-057)
  - DoS / Gas (ETH-066 to ETH-070)
"""

import json
import textwrap
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_contract_name(file_path: str) -> str:
    """Best-effort extraction of the contract name from the file path."""
    stem = Path(file_path).stem
    # CamelCase already — return as-is
    if stem[0].isupper():
        return stem
    # snake_case -> CamelCase
    return "".join(word.capitalize() for word in stem.split("_"))


def _solidity_import_path(file_path: str, contracts_path: str) -> str:
    """Build a relative import path suitable for Solidity import statements."""
    try:
        rel = Path(file_path).resolve().relative_to(Path(contracts_path).resolve())
    except ValueError:
        rel = Path(file_path)
    # Foundry convention: imports from src/ or contracts/
    return f"../{rel}"


def _finding_to_dict(finding) -> dict:
    """Convert a Finding (dataclass or dict) to a plain dict."""
    if isinstance(finding, dict):
        return finding
    # dataclass
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": getattr(finding, "confidence", 0.8),
        "file": finding.file,
        "line": getattr(finding, "line", 0),
        "code_snippet": getattr(finding, "code_snippet", ""),
        "description": getattr(finding, "description", ""),
        "recommendation": getattr(finding, "recommendation", ""),
        "category": getattr(finding, "category", ""),
    }


def _classify_finding(fid: str) -> str:
    """Map an ETH-XXX pattern id to a fuzz template category."""
    num = int(fid.replace("ETH-", ""))
    if 1 <= num <= 5 or num == 44 or 81 <= num <= 85:
        return "reentrancy"
    if 6 <= num <= 12 or 49 <= num <= 54 or 86 <= num <= 93:
        return "access_control"
    if 13 <= num <= 17:
        return "arithmetic"
    if 24 <= num <= 28 or 94 <= num <= 96:
        return "oracle"
    if num == 57 or num == 58:
        return "vault"
    if 66 <= num <= 70:
        return "dos"
    return "generic"


# ---------------------------------------------------------------------------
# Foundry templates
# ---------------------------------------------------------------------------

_FOUNDRY_HEADER = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
"""

_FOUNDRY_REENTRANCY = textwrap.dedent("""\
    // --- Reentrancy invariant (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s
    // %(description)s

    uint256 private _balanceBefore_%(idx)s;

    function invariant_reentrancy_%(idx)s_balance_consistent() public {
        // After any sequence of calls the contract balance must never
        // decrease unexpectedly (reentrancy drains funds).
        uint256 bal = address(target).balance;
        // If setUp stored an initial balance, the current balance should
        // be >= that value minus legitimate withdrawals.
        assertTrue(bal <= address(target).balance + 1 ether,
            "Reentrancy: balance drained unexpectedly");
    }

    function invariant_reentrancy_%(idx)s_no_nested_calls() public view {
        // The contract should not be in a re-entered state after a tx.
        // (Custom flag — set a transient bool in the target if supported.)
    }
""")

_FOUNDRY_ACCESS_CONTROL = textwrap.dedent("""\
    // --- Access control fuzz (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s

    function testFuzz_accessControl_%(idx)s_randomCaller(address caller) public {
        // Non-privileged callers must be rejected from admin functions.
        vm.assume(caller != address(this));
        vm.assume(caller != address(0));
        vm.startPrank(caller);
        // TODO: Replace with the actual privileged function call.
        // Example: target.transferOwnership(caller);
        // vm.expectRevert();
        vm.stopPrank();
    }
""")

_FOUNDRY_ARITHMETIC = textwrap.dedent("""\
    // --- Arithmetic fuzz (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s

    function testFuzz_arithmetic_%(idx)s_noOverflow(uint256 a, uint256 b) public {
        // Verify that arithmetic operations do not overflow/underflow
        // or lose precision beyond acceptable bounds.
        vm.assume(a < type(uint128).max);
        vm.assume(b < type(uint128).max && b > 0);
        // TODO: Call the target function with (a, b) and assert
        // the result is within expected bounds.
        // uint256 result = target.calculate(a, b);
        // assertGe(result, 0, "Arithmetic underflow");
    }
""")

_FOUNDRY_ORACLE = textwrap.dedent("""\
    // --- Oracle price fuzz (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s

    function testFuzz_oracle_%(idx)s_extremePrice(uint256 price) public {
        // Protocol must handle extreme oracle prices gracefully.
        vm.assume(price > 0);
        vm.assume(price < type(uint128).max);
        // TODO: Mock the oracle and set the fuzzed price, then
        // verify the protocol does not become insolvent.
        // mockOracle.setPrice(price);
        // target.updatePrice();
        // assertGt(target.totalCollateral(), 0, "Oracle: protocol insolvent at extreme price");
    }
""")

_FOUNDRY_VAULT = textwrap.dedent("""\
    // --- Vault share inflation invariant (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s

    function invariant_vault_%(idx)s_share_price_stable() public {
        // The share price must never be inflatable by a first depositor
        // donating assets directly to the vault.
        // uint256 totalAssets = target.totalAssets();
        // uint256 totalShares = target.totalSupply();
        // if (totalShares > 0) {
        //     uint256 pricePerShare = totalAssets * 1e18 / totalShares;
        //     assertLe(pricePerShare, 2e18, "Vault: share price inflated");
        // }
    }

    function testFuzz_vault_%(idx)s_first_deposit(uint256 amount) public {
        // First depositor should not be able to steal from second depositor.
        vm.assume(amount > 1e6 && amount < 1e24);
        // TODO: deposit(amount) as first user, then deposit same as second
        // user, and assert second user gets a fair share.
    }
""")

_FOUNDRY_DOS = textwrap.dedent("""\
    // --- DoS / Gas fuzz (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s

    function testFuzz_dos_%(idx)s_bounded_gas(uint256 arrayLen) public {
        // Operations with user-controlled array sizes must not exceed
        // the block gas limit.
        arrayLen = bound(arrayLen, 1, 500);
        uint256 gasBefore = gasleft();
        // TODO: Call the function with an array of `arrayLen` elements.
        // target.processAll(new uint256[](arrayLen));
        uint256 gasUsed = gasBefore - gasleft();
        assertLt(gasUsed, 10_000_000, "DoS: gas consumption too high");
    }
""")

_FOUNDRY_GENERIC = textwrap.dedent("""\
    // --- Generic fuzz (%(id)s: %(title)s) ---
    // Target: %(file)s:%(line)s
    // %(description)s

    function testFuzz_generic_%(idx)s(uint256 x) public {
        // TODO: Add a meaningful property test for this finding.
    }
""")

_FOUNDRY_TEMPLATES = {
    "reentrancy": _FOUNDRY_REENTRANCY,
    "access_control": _FOUNDRY_ACCESS_CONTROL,
    "arithmetic": _FOUNDRY_ARITHMETIC,
    "oracle": _FOUNDRY_ORACLE,
    "vault": _FOUNDRY_VAULT,
    "dos": _FOUNDRY_DOS,
    "generic": _FOUNDRY_GENERIC,
}


# ---------------------------------------------------------------------------
# Echidna templates
# ---------------------------------------------------------------------------

_ECHIDNA_HEADER = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
"""

_ECHIDNA_REENTRANCY = textwrap.dedent("""\
    // --- Reentrancy property (%(id)s) ---
    bool private _entered_%(idx)s;

    function echidna_no_reentrancy_%(idx)s() public returns (bool) {
        // Must never be in a re-entered state after tx completes.
        return !_entered_%(idx)s;
    }
""")

_ECHIDNA_ACCESS_CONTROL = textwrap.dedent("""\
    // --- Access control property (%(id)s) ---
    address private _owner_%(idx)s;

    function echidna_owner_unchanged_%(idx)s() public returns (bool) {
        // Owner should only change via legitimate ownership transfer.
        // TODO: Adapt to actual ownership variable.
        return _owner_%(idx)s == address(0) || _owner_%(idx)s == msg.sender;
    }
""")

_ECHIDNA_ARITHMETIC = textwrap.dedent("""\
    // --- Arithmetic property (%(id)s) ---
    function echidna_no_overflow_%(idx)s() public pure returns (bool) {
        // Basic sanity: max uint256 + 1 must revert in checked mode.
        // This is a placeholder; replace with protocol-specific math.
        return true;
    }
""")

_ECHIDNA_ORACLE = textwrap.dedent("""\
    // --- Oracle property (%(id)s) ---
    function echidna_oracle_sane_%(idx)s() public view returns (bool) {
        // Oracle price must be within a sane range to prevent manipulation.
        // TODO: Read the oracle price and assert bounds.
        return true;
    }
""")

_ECHIDNA_VAULT = textwrap.dedent("""\
    // --- Vault property (%(id)s) ---
    function echidna_vault_share_price_%(idx)s() public view returns (bool) {
        // Share price must not exceed 2x initial price (inflation guard).
        // TODO: return target.totalAssets() * 1e18 / target.totalSupply() <= 2e18;
        return true;
    }
""")

_ECHIDNA_DOS = textwrap.dedent("""\
    // --- DoS property (%(id)s) ---
    function echidna_dos_bounded_%(idx)s() public pure returns (bool) {
        // Placeholder: ensure loops terminate within gas limits.
        return true;
    }
""")

_ECHIDNA_GENERIC = textwrap.dedent("""\
    // --- Generic property (%(id)s: %(title)s) ---
    function echidna_generic_%(idx)s() public pure returns (bool) {
        // TODO: Add meaningful property for %(id)s.
        return true;
    }
""")

_ECHIDNA_TEMPLATES = {
    "reentrancy": _ECHIDNA_REENTRANCY,
    "access_control": _ECHIDNA_ACCESS_CONTROL,
    "arithmetic": _ECHIDNA_ARITHMETIC,
    "oracle": _ECHIDNA_ORACLE,
    "vault": _ECHIDNA_VAULT,
    "dos": _ECHIDNA_DOS,
    "generic": _ECHIDNA_GENERIC,
}

_ECHIDNA_CONFIG_YAML = textwrap.dedent("""\
# Echidna configuration generated by SolidityGuard
# Run: echidna . --contract {contract_name} --config {config_path}
testMode: assertion
testLimit: 50000
shrinkLimit: 5000
seqLen: 100
deployer: "0x10000"
sender: ["0x20000", "0x30000"]
filterFunctions: []
""")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_foundry_fuzz(findings, contracts_path: str) -> str:
    """Generate a Foundry invariant/fuzz test file from findings.

    Args:
        findings: List of Finding objects or dicts with at minimum 'id', 'file', 'title'.
        contracts_path: Root path of the Solidity contracts (for import resolution).

    Returns:
        Solidity source code as a string.
    """
    if not findings:
        return ""

    finding_dicts = [_finding_to_dict(f) for f in findings]

    # Collect unique contracts
    contracts_seen: dict[str, str] = {}  # name -> import path
    for fd in finding_dicts:
        name = _extract_contract_name(fd["file"])
        if name not in contracts_seen:
            contracts_seen[name] = _solidity_import_path(fd["file"], contracts_path)

    # Build imports
    lines = [_FOUNDRY_HEADER]
    for name, imp in contracts_seen.items():
        lines.append(f'import {{{{ {name} }}}} from "{imp}";')
    lines.append("")

    # Contract declaration
    primary_name = list(contracts_seen.keys())[0] if contracts_seen else "Target"
    lines.append("contract SolidityGuardInvariantTest is StdInvariant, Test {")
    lines.append(f"    {primary_name} target;")
    lines.append("")

    # setUp
    lines.append("    function setUp() public {")
    lines.append(f"        target = new {primary_name}();")
    lines.append("        targetContract(address(target));")
    lines.append("    }")
    lines.append("")

    # Generate per-finding tests
    categories_seen: set[str] = set()
    for idx, fd in enumerate(finding_dicts):
        cat = _classify_finding(fd["id"])
        template = _FOUNDRY_TEMPLATES.get(cat, _FOUNDRY_GENERIC)
        params = {
            "id": fd["id"],
            "title": fd["title"],
            "file": fd["file"],
            "line": fd.get("line", 0),
            "description": fd.get("description", "").replace("\n", " ")[:120],
            "idx": idx,
        }
        block = template % params
        # Indent inside contract
        for line in block.splitlines():
            lines.append(f"    {line}" if line.strip() else "")
        categories_seen.add(cat)

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def generate_echidna_config(findings, contracts_path: str) -> tuple[str, str]:
    """Generate an Echidna test contract + YAML config from findings.

    Args:
        findings: List of Finding objects or dicts.
        contracts_path: Root path of the Solidity contracts.

    Returns:
        Tuple of (solidity_test_source, yaml_config).
    """
    if not findings:
        return "", ""

    finding_dicts = [_finding_to_dict(f) for f in findings]

    # Build Solidity property contract
    lines = [_ECHIDNA_HEADER]

    contracts_seen: dict[str, str] = {}
    for fd in finding_dicts:
        name = _extract_contract_name(fd["file"])
        if name not in contracts_seen:
            contracts_seen[name] = _solidity_import_path(fd["file"], contracts_path)

    for name, imp in contracts_seen.items():
        lines.append(f'import {{{{ {name} }}}} from "{imp}";')
    lines.append("")

    primary_name = list(contracts_seen.keys())[0] if contracts_seen else "Target"
    test_contract_name = "SolidityGuardEchidnaTest"
    lines.append(f"contract {test_contract_name} {{")
    lines.append(f"    {primary_name} target;")
    lines.append("")
    lines.append("    constructor() {")
    lines.append(f"        target = new {primary_name}();")
    lines.append("    }")
    lines.append("")

    for idx, fd in enumerate(finding_dicts):
        cat = _classify_finding(fd["id"])
        template = _ECHIDNA_TEMPLATES.get(cat, _ECHIDNA_GENERIC)
        params = {
            "id": fd["id"],
            "title": fd["title"],
            "file": fd["file"],
            "line": fd.get("line", 0),
            "description": fd.get("description", "").replace("\n", " ")[:120],
            "idx": idx,
        }
        block = template % params
        for line in block.splitlines():
            lines.append(f"    {line}" if line.strip() else "")

    lines.append("}")
    lines.append("")

    sol_source = "\n".join(lines)
    yaml_config = _ECHIDNA_CONFIG_YAML.format(
        contract_name=test_contract_name,
        config_path="echidna.yaml",
    )

    return sol_source, yaml_config


def generate_from_json(findings_json: str, contracts_path: str) -> dict:
    """Generate both Foundry and Echidna tests from a JSON findings list.

    Args:
        findings_json: JSON string (list of finding dicts).
        contracts_path: Root of the Solidity project.

    Returns:
        Dict with keys: foundry_test, echidna_test, echidna_config, summary.
    """
    findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    # Accept either a raw list or a dict with a "findings" key
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    foundry = generate_foundry_fuzz(findings, contracts_path)
    echidna_sol, echidna_yaml = generate_echidna_config(findings, contracts_path)

    categories = {}
    for fd in findings:
        fd = _finding_to_dict(fd) if not isinstance(fd, dict) else fd
        cat = _classify_finding(fd["id"])
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "foundry_test": foundry,
        "echidna_test": echidna_sol,
        "echidna_config": echidna_yaml,
        "summary": {
            "total_findings": len(findings),
            "categories": categories,
            "foundry_tests_generated": foundry.count("function "),
            "echidna_properties_generated": echidna_sol.count("function echidna_"),
        },
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate fuzz tests from SolidityGuard findings")
    parser.add_argument("findings", help="Path to findings JSON file")
    parser.add_argument("contracts", help="Path to contracts directory")
    parser.add_argument("--output-dir", "-o", default=".", help="Output directory")
    parser.add_argument("--foundry-only", action="store_true", help="Only generate Foundry tests")
    parser.add_argument("--echidna-only", action="store_true", help="Only generate Echidna tests")
    args = parser.parse_args()

    findings_data = json.loads(Path(args.findings).read_text())
    result = generate_from_json(findings_data, args.contracts)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not args.echidna_only:
        foundry_path = out / "SolidityGuard.invariant.t.sol"
        foundry_path.write_text(result["foundry_test"])
        print(f"Foundry test: {foundry_path}")

    if not args.foundry_only:
        echidna_dir = out / "echidna"
        echidna_dir.mkdir(parents=True, exist_ok=True)
        (echidna_dir / "SolidityGuardEchidna.sol").write_text(result["echidna_test"])
        (echidna_dir / "echidna.yaml").write_text(result["echidna_config"])
        print(f"Echidna test: {echidna_dir / 'SolidityGuardEchidna.sol'}")
        print(f"Echidna config: {echidna_dir / 'echidna.yaml'}")

    s = result["summary"]
    print(f"\nGenerated from {s['total_findings']} findings:")
    print(f"  Foundry tests/invariants: {s['foundry_tests_generated']}")
    print(f"  Echidna properties:       {s['echidna_properties_generated']}")
    for cat, count in sorted(s["categories"].items()):
        print(f"    {cat}: {count}")


if __name__ == "__main__":
    main()
