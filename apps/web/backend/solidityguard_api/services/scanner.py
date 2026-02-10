"""Scanner service — wraps solidity_guard.py scan_patterns()."""

import importlib.util
import json
import subprocess
import shutil
from pathlib import Path

from solidityguard_api.models.schemas import Finding, PatternInfo, ToolStatus

# Import solidity_guard from the skills directory
# Docker: scripts at /app/scripts/
# Dev: __file__ = .../apps/web/backend/solidityguard_api/services/scanner.py → parents[5] = repo root
_DOCKER_SCRIPTS = Path("/app/scripts")
if _DOCKER_SCRIPTS.is_dir() and (_DOCKER_SCRIPTS / "solidity_guard.py").exists():
    _SCANNER_PATH = _DOCKER_SCRIPTS / "solidity_guard.py"
    _REPORT_GEN_PATH = _DOCKER_SCRIPTS / "report_generator.py"
else:
    _REPO_ROOT = Path(__file__).resolve().parents[5]
    _SCANNER_PATH = _REPO_ROOT / ".claude" / "skills" / "solidity-guard" / "scripts" / "solidity_guard.py"
    _REPORT_GEN_PATH = _REPO_ROOT / ".claude" / "skills" / "solidity-guard" / "scripts" / "report_generator.py"

def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_scanner = _load_module("solidity_guard", _SCANNER_PATH)
_report_gen = _load_module("report_generator", _REPORT_GEN_PATH)


def _normalize_severity(severity: str) -> str:
    """Normalize severity to match frontend expectations (CRITICAL/HIGH/MEDIUM/LOW/INFO)."""
    s = severity.upper()
    if s == "INFORMATIONAL":
        return "INFO"
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return s
    return "INFO"


def _raw_to_finding(f) -> Finding:
    """Convert a raw finding (dataclass or dict) to a Finding model."""
    d = f.to_dict() if hasattr(f, "to_dict") else f
    return Finding(
        id=d.get("id", ""),
        title=d.get("title", ""),
        severity=_normalize_severity(d.get("severity", "INFO")),
        confidence=d.get("confidence", 0.0),
        file=d.get("file", ""),
        line=d.get("line", 0),
        code_snippet=d.get("code_snippet", ""),
        description=d.get("description", ""),
        remediation=d.get("recommendation", ""),
        category=d.get("category", ""),
        swc=d.get("swc"),
        tool=d.get("tool", "pattern-scanner"),
    )


def run_mythril(target_path: str) -> list:
    """Run Mythril symbolic execution and parse JSON results."""
    findings = []
    sol_files = list(Path(target_path).rglob("*.sol")) if Path(target_path).is_dir() else [Path(target_path)]

    for sol_file in sol_files:
        try:
            result = subprocess.run(
                ["myth", "analyze", str(sol_file), "-o", "json"],
                capture_output=True, text=True, timeout=600,
            )
            if not result.stdout:
                continue
            data = json.loads(result.stdout)

            severity_map = {
                "High": "HIGH",
                "Medium": "MEDIUM",
                "Low": "LOW",
            }

            for issue in data.get("issues", []):
                lineno = issue.get("lineno", 0) or 0
                findings.append(Finding(
                    id=f"MYTHRIL-{issue.get('swc-id', 'unknown')}",
                    title=issue.get("title", "Unknown"),
                    severity=severity_map.get(issue.get("severity", ""), "MEDIUM"),
                    confidence=0.85,
                    file=str(sol_file.relative_to(target_path)) if Path(target_path).is_dir() else str(sol_file),
                    line=int(lineno),
                    code_snippet=issue.get("code", ""),
                    description=issue.get("description", ""),
                    remediation=f"SWC-{issue.get('swc-id', 'N/A')}: {issue.get('swc-title', '')}",
                    category=issue.get("swc-title", "unknown").lower().replace(" ", "-"),
                    swc=f"SWC-{issue.get('swc-id')}" if issue.get("swc-id") else None,
                    tool="mythril",
                ))
        except FileNotFoundError:
            break  # myth not installed, no point trying other files
        except subprocess.TimeoutExpired:
            continue
        except (json.JSONDecodeError, KeyError):
            continue

    return findings


def run_scan(target_path: str, tools: list[str] | None = None) -> list[Finding]:
    """Run the pattern scanner on a target path and return findings."""
    tools = tools or ["pattern"]
    raw_findings: list = []

    if "pattern" in tools:
        raw_findings.extend(_scanner.scan_patterns(target_path))

    if "slither" in tools:
        raw_findings.extend(_scanner.run_slither(target_path))

    if "aderyn" in tools:
        raw_findings.extend(_scanner.run_aderyn(target_path))

    findings = [_raw_to_finding(f) for f in raw_findings]

    if "mythril" in tools:
        findings.extend(run_mythril(target_path))

    return findings


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings from multiple tools.

    When multiple tools flag the same file+line (within 3 lines), keep the
    highest-confidence entry and record all contributing tools in the
    description.
    """
    if not findings:
        return findings

    # Group by (file, approximate_line) — lines within 3 of each other are same
    groups: dict[tuple[str, int], list[Finding]] = {}
    for f in findings:
        # Normalize line to nearest bucket of 3
        bucket_line = (f.line // 3) * 3
        key = (f.file, bucket_line)
        groups.setdefault(key, []).append(f)

    deduped: list[Finding] = []
    for _key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        # Sort by confidence descending, keep best
        group.sort(key=lambda x: x.confidence, reverse=True)
        best = group[0]

        # Collect all tool names
        all_tools = sorted(set(g.tool for g in group))
        tools_str = ", ".join(all_tools)

        # Create merged finding
        merged = best.model_copy(update={
            "description": f"[Confirmed by: {tools_str}] {best.description}",
            "confidence": min(best.confidence + 0.05 * (len(all_tools) - 1), 0.95),
        })
        deduped.append(merged)

    return deduped


def _build_scan_results(findings: list[Finding], project: str = "", tools_used: list[str] | None = None):
    """Build a ScanResults object from findings."""
    finding_dicts = []
    for f in findings:
        d = f.model_dump()
        d["recommendation"] = d.pop("remediation", "")
        finding_dicts.append(d)

    results = _scanner.ScanResults(
        project=project or "Audit",
        timestamp=__import__("datetime").datetime.now().isoformat(),
        tools_used=tools_used or ["pattern"],
    )
    for fd in finding_dicts:
        results.add_finding(_scanner.Finding(**{k: v for k, v in fd.items() if k != "tool"}))
    results.calculate_score()
    return results


def generate_report_markdown(findings: list[Finding], project: str = "", tools_used: list[str] | None = None) -> tuple[str, int, dict]:
    """Generate a markdown report from findings. Returns (markdown, score, summary)."""
    results = _build_scan_results(findings, project, tools_used)
    data = results.to_dict()
    markdown = _report_gen.generate_report(data, project=project)
    return markdown, results.security_score, results.summary


def generate_report_pdf(findings: list[Finding], project: str = "", tools_used: list[str] | None = None) -> bytes | None:
    """Generate a PDF report from findings. Returns PDF bytes or None if generation fails."""
    import tempfile
    results = _build_scan_results(findings, project, tools_used)
    data = results.to_dict()

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        pdf_path = tmp.name

    success = _report_gen.generate_pdf(data, pdf_path, project=project)
    if success:
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        import os
        os.unlink(pdf_path)
        return pdf_bytes

    import os
    if os.path.exists(pdf_path):
        os.unlink(pdf_path)
    return None


# All 104 patterns with metadata
PATTERNS: list[PatternInfo] = [
    PatternInfo(id="ETH-001", title="Single-function Reentrancy", severity="CRITICAL", category="reentrancy", swc="SWC-107", description="External call with value transfer before state update (CEI violation)."),
    PatternInfo(id="ETH-002", title="Cross-function Reentrancy", severity="CRITICAL", category="reentrancy", swc="SWC-107", description="Reentrancy across multiple functions sharing state."),
    PatternInfo(id="ETH-003", title="Cross-contract Reentrancy", severity="HIGH", category="reentrancy", swc="SWC-107", description="Reentrancy exploiting shared state across contracts."),
    PatternInfo(id="ETH-004", title="Read-only Reentrancy", severity="HIGH", category="reentrancy", description="View function returns manipulated state during reentrancy window."),
    PatternInfo(id="ETH-005", title="Cross-chain Reentrancy", severity="HIGH", category="reentrancy", description="Reentrancy via cross-chain message bridging."),
    PatternInfo(id="ETH-006", title="Missing Access Control", severity="CRITICAL", category="access-control", swc="SWC-105", description="Sensitive function lacks access control modifier."),
    PatternInfo(id="ETH-007", title="tx.origin Authentication", severity="CRITICAL", category="access-control", swc="SWC-115", description="tx.origin used for authentication (phishing vulnerable)."),
    PatternInfo(id="ETH-008", title="Unprotected selfdestruct", severity="CRITICAL", category="access-control", swc="SWC-106", description="selfdestruct without access control."),
    PatternInfo(id="ETH-009", title="Default Function Visibility", severity="HIGH", category="access-control", swc="SWC-100", description="Function visibility not explicitly declared."),
    PatternInfo(id="ETH-010", title="Uninitialized Proxy", severity="CRITICAL", category="proxy", description="Proxy initialize() callable by anyone."),
    PatternInfo(id="ETH-011", title="Missing Modifier on State-changing Function", severity="HIGH", category="access-control", description="State-changing function without modifier."),
    PatternInfo(id="ETH-012", title="Centralization Risk / Single Admin", severity="MEDIUM", category="access-control", description="Single admin key controls critical operations."),
    PatternInfo(id="ETH-013", title="Integer Overflow/Underflow", severity="HIGH", category="arithmetic", swc="SWC-101", description="Arithmetic overflow/underflow risk."),
    PatternInfo(id="ETH-014", title="Division Before Multiplication", severity="MEDIUM", category="arithmetic", description="Precision loss from dividing before multiplying."),
    PatternInfo(id="ETH-015", title="Unchecked Math in unchecked Block", severity="HIGH", category="arithmetic", description="Arithmetic in unchecked block without bounds checks."),
    PatternInfo(id="ETH-016", title="Rounding Errors", severity="MEDIUM", category="arithmetic", description="Integer rounding errors in calculations."),
    PatternInfo(id="ETH-017", title="Precision Loss in Token Calculations", severity="MEDIUM", category="arithmetic", description="Division by large denominators causing precision loss."),
    PatternInfo(id="ETH-018", title="Unchecked External Call Return", severity="HIGH", category="external-calls", swc="SWC-104", description="Low-level call return value not checked."),
    PatternInfo(id="ETH-019", title="Delegatecall to Untrusted Callee", severity="CRITICAL", category="external-calls", swc="SWC-112", description="delegatecall to untrusted contract."),
    PatternInfo(id="ETH-020", title="Unsafe Low-level Call", severity="HIGH", category="external-calls", description="Unsafe use of low-level call."),
    PatternInfo(id="ETH-021", title="DoS with Failed Call", severity="HIGH", category="external-calls", swc="SWC-113", description="External call failure causes DoS."),
    PatternInfo(id="ETH-022", title="Return Value Not Checked (ERC-20)", severity="HIGH", category="external-calls", description="ERC-20 return value not checked."),
    PatternInfo(id="ETH-023", title="Insufficient Gas Griefing", severity="MEDIUM", category="external-calls", swc="SWC-126", description="External call with insufficient gas forwarded."),
    PatternInfo(id="ETH-024", title="Oracle Manipulation", severity="CRITICAL", category="oracle", description="Price oracle manipulable via flash loans."),
    PatternInfo(id="ETH-025", title="Flash Loan Attack Vector", severity="CRITICAL", category="oracle", description="Flash loan-dependent state."),
    PatternInfo(id="ETH-026", title="Sandwich Attack / MEV", severity="HIGH", category="defi", description="Transaction vulnerable to sandwich attacks."),
    PatternInfo(id="ETH-027", title="Missing Slippage Protection", severity="HIGH", category="defi", description="Swap without minimum output amount."),
    PatternInfo(id="ETH-028", title="Stale Oracle Data", severity="HIGH", category="oracle", description="Oracle data used without staleness check."),
    PatternInfo(id="ETH-029", title="Uninitialized Storage Pointer", severity="HIGH", category="storage", swc="SWC-109", description="Storage pointer not initialized."),
    PatternInfo(id="ETH-030", title="Storage Collision (Proxy)", severity="CRITICAL", category="storage", swc="SWC-124", description="Storage layout collision in proxy pattern."),
    PatternInfo(id="ETH-031", title="Shadowing State Variables", severity="MEDIUM", category="storage", swc="SWC-119", description="State variable shadowed by inherited contract."),
    PatternInfo(id="ETH-032", title="Unexpected Ether Balance", severity="MEDIUM", category="logic", swc="SWC-132", description="Strict equality check on ether balance."),
    PatternInfo(id="ETH-033", title="Write to Arbitrary Storage Location", severity="CRITICAL", category="storage", swc="SWC-124", description="Arbitrary storage write via array length manipulation."),
    PatternInfo(id="ETH-034", title="Strict Equality on Balance", severity="HIGH", category="logic", swc="SWC-132", description="Strict balance equality breakable by attacker."),
    PatternInfo(id="ETH-035", title="Transaction Order Dependence", severity="HIGH", category="logic", swc="SWC-114", description="Transaction outcome depends on execution order."),
    PatternInfo(id="ETH-036", title="Timestamp Dependence", severity="MEDIUM", category="logic", swc="SWC-116", description="Block timestamp used for critical logic."),
    PatternInfo(id="ETH-037", title="Weak Randomness from Chain Attributes", severity="HIGH", category="logic", swc="SWC-120", description="Block attributes used for randomness (miner-manipulable)."),
    PatternInfo(id="ETH-038", title="Signature Malleability", severity="HIGH", category="logic", swc="SWC-117", description="ecrecover without address(0) check."),
    PatternInfo(id="ETH-039", title="Signature Replay Attack", severity="CRITICAL", category="logic", swc="SWC-121", description="Signature replayable across chains/contracts."),
    PatternInfo(id="ETH-040", title="Front-running Vulnerability", severity="HIGH", category="logic", swc="SWC-114", description="Transaction front-runnable for profit."),
    PatternInfo(id="ETH-041", title="ERC-20 Non-standard Return Values", severity="HIGH", category="token", description="ERC-20 transfer without SafeERC20."),
    PatternInfo(id="ETH-042", title="Fee-on-Transfer Token Incompatibility", severity="HIGH", category="token", description="No balance diff check for fee-on-transfer tokens."),
    PatternInfo(id="ETH-043", title="Rebasing Token Incompatibility", severity="HIGH", category="token", description="Protocol incompatible with rebasing tokens."),
    PatternInfo(id="ETH-044", title="ERC-777 Reentrancy Hook", severity="CRITICAL", category="token", description="ERC-777 hooks enable reentrancy."),
    PatternInfo(id="ETH-045", title="Missing Zero Address Check", severity="MEDIUM", category="token", description="Critical address setter without zero-address check."),
    PatternInfo(id="ETH-046", title="Approval Race Condition", severity="MEDIUM", category="token", description="ERC-20 approve race condition."),
    PatternInfo(id="ETH-047", title="Infinite Approval Risk", severity="LOW", category="token", description="Unlimited token approval risk."),
    PatternInfo(id="ETH-048", title="Token Supply Manipulation", severity="HIGH", category="token", description="Unprotected minting function."),
    PatternInfo(id="ETH-049", title="Uninitialized Implementation Contract", severity="CRITICAL", category="proxy", description="Missing _disableInitializers in constructor."),
    PatternInfo(id="ETH-050", title="Storage Layout Mismatch on Upgrade", severity="CRITICAL", category="proxy", description="Proxy and impl storage layouts diverge."),
    PatternInfo(id="ETH-051", title="Function Selector Clash", severity="HIGH", category="proxy", description="Proxy function selector collides with impl."),
    PatternInfo(id="ETH-052", title="Missing Upgrade Authorization", severity="CRITICAL", category="proxy", description="Upgrade function without access control."),
    PatternInfo(id="ETH-053", title="selfdestruct in Implementation", severity="HIGH", category="proxy", description="selfdestruct in upgradeable implementation."),
    PatternInfo(id="ETH-054", title="Transparent Proxy Selector Collision", severity="HIGH", category="proxy", description="Admin functions collide with impl selectors."),
    PatternInfo(id="ETH-055", title="Governance Manipulation", severity="HIGH", category="defi", description="Governance without vote snapshotting."),
    PatternInfo(id="ETH-056", title="Liquidation Manipulation", severity="HIGH", category="defi", description="Liquidation parameters manipulable."),
    PatternInfo(id="ETH-057", title="Vault Share Inflation / First Depositor", severity="CRITICAL", category="defi", description="First depositor can inflate share price."),
    PatternInfo(id="ETH-058", title="Donation Attack", severity="HIGH", category="defi", description="Direct token donation skews share ratio."),
    PatternInfo(id="ETH-059", title="AMM Constant Product Error", severity="CRITICAL", category="defi", description="Incorrect constant product formula in AMM."),
    PatternInfo(id="ETH-060", title="Missing Transaction Deadline", severity="MEDIUM", category="defi", description="Swap without deadline allows delayed execution."),
    PatternInfo(id="ETH-061", title="Unrestricted Flash Mint", severity="HIGH", category="defi", description="Flash mint without proper restrictions."),
    PatternInfo(id="ETH-062", title="Pool Imbalance Attack", severity="HIGH", category="defi", description="Liquidity pool imbalance exploitable."),
    PatternInfo(id="ETH-063", title="Reward Distribution Error", severity="HIGH", category="defi", description="Incorrect reward accrual calculation."),
    PatternInfo(id="ETH-064", title="Insecure Callback / Hook Handler", severity="HIGH", category="defi", description="Callback without sender validation."),
    PatternInfo(id="ETH-065", title="Cross-protocol Integration Risk", severity="MEDIUM", category="defi", description="User-supplied protocol address used in calls."),
    PatternInfo(id="ETH-066", title="Unbounded Loop / Array Growth", severity="HIGH", category="gas-dos", swc="SWC-128", description="Loop over dynamic array may exceed gas limit."),
    PatternInfo(id="ETH-067", title="Block Gas Limit DoS", severity="HIGH", category="gas-dos", swc="SWC-128", description="Operation exceeds block gas limit."),
    PatternInfo(id="ETH-068", title="Unexpected Revert in Loop", severity="MEDIUM", category="gas-dos", swc="SWC-113", description="Single revert in loop blocks entire operation."),
    PatternInfo(id="ETH-069", title="Griefing Attack", severity="MEDIUM", category="gas-dos", description="Attacker can grief other users at low cost."),
    PatternInfo(id="ETH-070", title="Storage Slot Exhaustion", severity="LOW", category="gas-dos", description="Unbounded storage growth."),
    PatternInfo(id="ETH-071", title="Floating Pragma", severity="LOW", category="miscellaneous", swc="SWC-103", description="Floating pragma allows different compiler versions."),
    PatternInfo(id="ETH-072", title="Outdated Compiler Version", severity="LOW", category="miscellaneous", swc="SWC-102", description="Old Solidity version missing security fixes."),
    PatternInfo(id="ETH-073", title="Hash Collision with abi.encodePacked", severity="MEDIUM", category="logic", swc="SWC-133", description="abi.encodePacked with dynamic types causes collisions."),
    PatternInfo(id="ETH-074", title="Right-to-Left Override Character", severity="HIGH", category="miscellaneous", swc="SWC-130", description="Unicode RTLO character hides malicious code."),
    PatternInfo(id="ETH-075", title="Code With No Effects", severity="LOW", category="miscellaneous", swc="SWC-135", description="Code that has no actual effect."),
    PatternInfo(id="ETH-076", title="Missing Event Emission", severity="LOW", category="miscellaneous", description="Critical state change without event."),
    PatternInfo(id="ETH-077", title="Incorrect Inheritance Order", severity="MEDIUM", category="miscellaneous", swc="SWC-125", description="C3 linearization order issues."),
    PatternInfo(id="ETH-078", title="Unencrypted Private Data On-Chain", severity="LOW", category="miscellaneous", swc="SWC-136", description="Private data readable via storage inspection."),
    PatternInfo(id="ETH-079", title="Hardcoded Gas Amount", severity="LOW", category="miscellaneous", swc="SWC-134", description=".transfer()/.send() forward only 2300 gas."),
    PatternInfo(id="ETH-080", title="Incorrect Constructor Name (legacy)", severity="HIGH", category="miscellaneous", swc="SWC-118", description="Constructor name mismatch in old Solidity."),
    PatternInfo(id="ETH-081", title="Transient Storage Slot Collision", severity="CRITICAL", category="transient-storage", description="TSTORE uses hardcoded small slot (collision risk)."),
    PatternInfo(id="ETH-082", title="Transient Storage Not Cleared", severity="HIGH", category="transient-storage", description="Transient storage not cleared after use."),
    PatternInfo(id="ETH-083", title="TSTORE Reentrancy Bypass", severity="CRITICAL", category="transient-storage", description="Reentrancy guard using transient storage bypassable."),
    PatternInfo(id="ETH-084", title="Transient Storage Delegatecall Exposure", severity="HIGH", category="transient-storage", description="Delegatecall exposes transient storage."),
    PatternInfo(id="ETH-085", title="Transient Storage Type-Safety Bypass", severity="MEDIUM", category="transient-storage", description="Type safety bypassed via transient storage."),
    PatternInfo(id="ETH-086", title="Broken tx.origin == msg.sender Assumption", severity="CRITICAL", category="access-control", description="EIP-7702 breaks tx.origin == msg.sender check."),
    PatternInfo(id="ETH-087", title="Malicious EIP-7702 Delegation", severity="HIGH", category="access-control", description="Malicious delegation target in EIP-7702."),
    PatternInfo(id="ETH-088", title="EIP-7702 Cross-Chain Authorization Replay", severity="CRITICAL", category="access-control", description="Authorization replayable across chains."),
    PatternInfo(id="ETH-089", title="EOA Code Assumption Failure", severity="HIGH", category="access-control", description="extcodesize/isContract unreliable after EIP-7702."),
    PatternInfo(id="ETH-090", title="UserOp Hash Collision", severity="HIGH", category="account-abstraction", description="UserOperation hash collision in ERC-4337."),
    PatternInfo(id="ETH-091", title="Paymaster Exploitation", severity="CRITICAL", category="account-abstraction", description="Paymaster validates insufficient data."),
    PatternInfo(id="ETH-092", title="Bundler Manipulation", severity="HIGH", category="account-abstraction", description="Bundler can manipulate UserOp execution."),
    PatternInfo(id="ETH-093", title="Validation-Execution Phase Confusion", severity="CRITICAL", category="account-abstraction", description="State assumptions between validation and execution phases."),
    PatternInfo(id="ETH-094", title="Uniswap V4 Hook Callback Authorization", severity="CRITICAL", category="modern-defi", description="Hook callback without pool manager verification."),
    PatternInfo(id="ETH-095", title="Hook Data Manipulation", severity="HIGH", category="modern-defi", description="Hook data not validated before use."),
    PatternInfo(id="ETH-096", title="Cached State Desynchronization", severity="HIGH", category="modern-defi", description="Cached state diverges from actual contract state."),
    PatternInfo(id="ETH-097", title="Known Compiler Bug in Used Version", severity="HIGH", category="miscellaneous", description="Solidity version with known compiler bug."),
    PatternInfo(id="ETH-098", title="Missing Input Validation / Boundary Check", severity="HIGH", category="input-validation", description="External function without parameter validation."),
    PatternInfo(id="ETH-099", title="Unsafe ABI Decoding / Calldata Manipulation", severity="HIGH", category="input-validation", description="ABI decoding without proper validation."),
    PatternInfo(id="ETH-100", title="EIP-7702 Delegation Phishing", severity="CRITICAL", category="off-chain", description="Phishing via malicious EIP-7702 delegation."),
    PatternInfo(id="ETH-101", title="Off-Chain Infrastructure Compromise", severity="CRITICAL", category="off-chain", description="UI/signer/multisig infrastructure compromise."),
    PatternInfo(id="ETH-102", title="Restaking Cascading Slashing Risk", severity="HIGH", category="restaking-l2", description="Cascading slashing across restaking protocols."),
    PatternInfo(id="ETH-103", title="L2 Sequencer Dependency", severity="HIGH", category="restaking-l2", description="Protocol depends on L2 sequencer liveness."),
    PatternInfo(id="ETH-104", title="L2 Cross-Domain Message Replay", severity="CRITICAL", category="restaking-l2", description="Cross-domain message replayable across L2s."),
]

PATTERNS_BY_ID: dict[str, PatternInfo] = {p.id: p for p in PATTERNS}


def check_tool(name: str) -> ToolStatus:
    """Check if a security tool is available on the system."""
    import subprocess
    cmd_map = {
        "slither": "slither",
        "aderyn": "aderyn",
        "mythril": "myth",
        "foundry": "forge",
        "echidna": "echidna",
        "medusa": "medusa",
        "halmos": "halmos",
        "certora": "certoraRun",
    }
    binary = cmd_map.get(name, name)
    available = shutil.which(binary) is not None
    version = None
    if available:
        try:
            result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
            version = result.stdout.strip().split("\n")[0][:80] if result.stdout else None
        except Exception:
            pass
    return ToolStatus(name=name, available=available, version=version)


ALL_TOOLS = ["slither", "aderyn", "mythril", "foundry", "echidna", "medusa", "halmos", "certora"]
