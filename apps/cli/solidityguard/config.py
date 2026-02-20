"""CLI configuration and path resolution."""

from pathlib import Path


def get_project_root() -> Path:
    """Return the solidity-audit repository root."""
    # Walk up from this file to find the repo root (contains CLAUDE.md)
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "CLAUDE.md").exists():
            return parent
    # Fallback: assume standard layout apps/cli/solidityguard/config.py
    return current.parent.parent.parent.parent


def get_scripts_dir() -> Path:
    """Return the path to the scanner scripts directory."""
    # Docker: scripts are at /app/scripts/
    docker_scripts = Path("/app/scripts")
    if docker_scripts.is_dir() and (docker_scripts / "solidity_guard.py").exists():
        return docker_scripts
    return get_project_root() / ".claude" / "skills" / "solidity-guard" / "scripts"


def get_scanner_path() -> Path:
    """Return the path to solidity_guard.py."""
    return get_scripts_dir() / "solidity_guard.py"


def get_benchmark_path() -> Path:
    """Return the path to ctf_benchmark.py."""
    return get_scripts_dir() / "ctf_benchmark.py"


def get_evmbench_path() -> Path:
    """Return the path to evmbench_local_benchmark.py."""
    return get_scripts_dir() / "evmbench_local_benchmark.py"


# Vulnerability pattern categories and their ETH-ID ranges
PATTERN_CATEGORIES = {
    "reentrancy": {
        "name": "Reentrancy",
        "ids": ["ETH-001", "ETH-002", "ETH-003", "ETH-004", "ETH-005"],
        "description": "Reentrancy attacks (single, cross-function, cross-contract, read-only, cross-chain)",
    },
    "access-control": {
        "name": "Access Control",
        "ids": [f"ETH-{i:03d}" for i in range(6, 13)],
        "description": "Missing access control, tx.origin, selfdestruct, proxy, centralization",
    },
    "arithmetic": {
        "name": "Arithmetic",
        "ids": [f"ETH-{i:03d}" for i in range(13, 18)],
        "description": "Integer overflow/underflow, division errors, precision loss",
    },
    "external-calls": {
        "name": "External Calls",
        "ids": [f"ETH-{i:03d}" for i in range(18, 24)],
        "description": "Unchecked returns, delegatecall, DoS, gas griefing",
    },
    "oracle": {
        "name": "Oracle & Price",
        "ids": [f"ETH-{i:03d}" for i in range(24, 29)],
        "description": "Oracle manipulation, flash loan, MEV, slippage, staleness",
    },
    "storage": {
        "name": "Storage & State",
        "ids": [f"ETH-{i:03d}" for i in range(29, 34)],
        "description": "Uninitialized storage, collision, shadowing, unexpected ether",
    },
    "logic": {
        "name": "Logic Errors",
        "ids": [f"ETH-{i:03d}" for i in range(34, 41)],
        "description": "Strict equality, TOD, timestamp, randomness, signature",
    },
    "token": {
        "name": "Token Issues",
        "ids": [f"ETH-{i:03d}" for i in range(41, 49)],
        "description": "Non-standard returns, fee-on-transfer, rebasing, ERC-777",
    },
    "proxy": {
        "name": "Proxy & Upgrade",
        "ids": [f"ETH-{i:03d}" for i in range(49, 55)],
        "description": "Uninitialized impl, storage mismatch, upgrade auth",
    },
    "defi": {
        "name": "DeFi Specific",
        "ids": [f"ETH-{i:03d}" for i in range(55, 66)],
        "description": "Governance, liquidation, vault inflation, AMM, flash mint",
    },
    "gas-dos": {
        "name": "Gas & DoS",
        "ids": [f"ETH-{i:03d}" for i in range(66, 71)],
        "description": "Unbounded loops, gas limit, revert in loop, griefing",
    },
    "miscellaneous": {
        "name": "Miscellaneous",
        "ids": [f"ETH-{i:03d}" for i in range(71, 81)],
        "description": "Floating pragma, outdated compiler, encodePacked, events",
    },
    "transient-storage": {
        "name": "Transient Storage (EIP-1153)",
        "ids": [f"ETH-{i:03d}" for i in range(81, 86)],
        "description": "Slot collision, not cleared, TSTORE reentry bypass",
    },
    "eip-7702": {
        "name": "EIP-7702 / Pectra",
        "ids": [f"ETH-{i:03d}" for i in range(86, 90)],
        "description": "Broken tx.origin==msg.sender, delegation, cross-chain replay",
    },
    "account-abstraction": {
        "name": "Account Abstraction (ERC-4337)",
        "ids": [f"ETH-{i:03d}" for i in range(90, 94)],
        "description": "UserOp collision, paymaster, bundler, validation phase",
    },
    "modern-defi": {
        "name": "Modern DeFi",
        "ids": [f"ETH-{i:03d}" for i in range(94, 98)],
        "description": "Uniswap V4 hooks, cached state, compiler bugs",
    },
    "input-validation": {
        "name": "Input Validation",
        "ids": ["ETH-098", "ETH-099"],
        "description": "Boundary checks, unsafe ABI decoding (OWASP 2025 #4)",
    },
    "off-chain": {
        "name": "Off-Chain & Infrastructure",
        "ids": ["ETH-100", "ETH-101"],
        "description": "EIP-7702 phishing, UI/signer compromise (Bybit pattern)",
    },
    "restaking-l2": {
        "name": "Restaking & L2",
        "ids": ["ETH-102", "ETH-103", "ETH-104"],
        "description": "Cascading slashing, sequencer deps, message replay",
    },
}

# Full pattern list (all 104)
ALL_PATTERNS = [
    # Reentrancy
    ("ETH-001", "Single-function Reentrancy", "CRITICAL", "SWC-107", "reentrancy"),
    ("ETH-002", "Cross-function Reentrancy", "CRITICAL", "SWC-107", "reentrancy"),
    ("ETH-003", "Cross-contract Reentrancy", "HIGH", "SWC-107", "reentrancy"),
    ("ETH-004", "Read-only Reentrancy", "HIGH", None, "reentrancy"),
    ("ETH-005", "Cross-chain Reentrancy", "HIGH", None, "reentrancy"),
    # Access Control
    ("ETH-006", "Missing Access Control", "CRITICAL", "SWC-105", "access-control"),
    ("ETH-007", "tx.origin Authentication", "CRITICAL", "SWC-115", "access-control"),
    ("ETH-008", "Unprotected selfdestruct", "CRITICAL", "SWC-106", "access-control"),
    ("ETH-009", "Default Function Visibility", "HIGH", "SWC-100", "access-control"),
    ("ETH-010", "Uninitialized Proxy", "CRITICAL", None, "access-control"),
    ("ETH-011", "Missing Modifier on State-changing Function", "HIGH", None, "access-control"),
    ("ETH-012", "Centralization Risk / Single Admin", "MEDIUM", None, "access-control"),
    # Arithmetic
    ("ETH-013", "Integer Overflow/Underflow", "HIGH", "SWC-101", "arithmetic"),
    ("ETH-014", "Division Before Multiplication", "MEDIUM", None, "arithmetic"),
    ("ETH-015", "Unchecked Math in unchecked Block", "HIGH", None, "arithmetic"),
    ("ETH-016", "Rounding Errors", "MEDIUM", None, "arithmetic"),
    ("ETH-017", "Precision Loss in Token Calculations", "MEDIUM", None, "arithmetic"),
    # External Calls
    ("ETH-018", "Unchecked External Call Return", "HIGH", "SWC-104", "external-calls"),
    ("ETH-019", "Delegatecall to Untrusted Callee", "CRITICAL", "SWC-112", "external-calls"),
    ("ETH-020", "Unsafe Low-level Call", "HIGH", None, "external-calls"),
    ("ETH-021", "DoS with Failed Call", "HIGH", "SWC-113", "external-calls"),
    ("ETH-022", "Return Value Not Checked (ERC-20)", "HIGH", None, "external-calls"),
    ("ETH-023", "Insufficient Gas Griefing", "MEDIUM", "SWC-126", "external-calls"),
    # Oracle & Price
    ("ETH-024", "Oracle Manipulation", "CRITICAL", None, "oracle"),
    ("ETH-025", "Flash Loan Attack Vector", "CRITICAL", None, "oracle"),
    ("ETH-026", "Sandwich Attack / MEV", "HIGH", None, "oracle"),
    ("ETH-027", "Missing Slippage Protection", "HIGH", None, "oracle"),
    ("ETH-028", "Stale Oracle Data", "HIGH", None, "oracle"),
    # Storage & State
    ("ETH-029", "Uninitialized Storage Pointer", "HIGH", "SWC-109", "storage"),
    ("ETH-030", "Storage Collision (Proxy)", "CRITICAL", "SWC-124", "storage"),
    ("ETH-031", "Shadowing State Variables", "MEDIUM", "SWC-119", "storage"),
    ("ETH-032", "Unexpected Ether Balance", "MEDIUM", "SWC-132", "storage"),
    ("ETH-033", "Write to Arbitrary Storage Location", "CRITICAL", "SWC-124", "storage"),
    # Logic Errors
    ("ETH-034", "Strict Equality on Balance", "HIGH", "SWC-132", "logic"),
    ("ETH-035", "Transaction Order Dependence", "HIGH", "SWC-114", "logic"),
    ("ETH-036", "Timestamp Dependence", "MEDIUM", "SWC-116", "logic"),
    ("ETH-037", "Weak Randomness from Chain Attributes", "HIGH", "SWC-120", "logic"),
    ("ETH-038", "Signature Malleability", "HIGH", "SWC-117", "logic"),
    ("ETH-039", "Signature Replay Attack", "CRITICAL", "SWC-121", "logic"),
    ("ETH-040", "Front-running Vulnerability", "HIGH", "SWC-114", "logic"),
    # Token Issues
    ("ETH-041", "ERC-20 Non-standard Return Values", "HIGH", None, "token"),
    ("ETH-042", "Fee-on-Transfer Token Incompatibility", "HIGH", None, "token"),
    ("ETH-043", "Rebasing Token Incompatibility", "HIGH", None, "token"),
    ("ETH-044", "ERC-777 Reentrancy Hook", "CRITICAL", None, "token"),
    ("ETH-045", "Missing Zero Address Check", "MEDIUM", None, "token"),
    ("ETH-046", "Approval Race Condition", "MEDIUM", None, "token"),
    ("ETH-047", "Infinite Approval Risk", "LOW", None, "token"),
    ("ETH-048", "Token Supply Manipulation", "HIGH", None, "token"),
    # Proxy & Upgrade
    ("ETH-049", "Uninitialized Implementation Contract", "CRITICAL", None, "proxy"),
    ("ETH-050", "Storage Layout Mismatch on Upgrade", "CRITICAL", None, "proxy"),
    ("ETH-051", "Function Selector Clash", "HIGH", None, "proxy"),
    ("ETH-052", "Missing Upgrade Authorization", "CRITICAL", None, "proxy"),
    ("ETH-053", "selfdestruct in Implementation", "HIGH", None, "proxy"),
    ("ETH-054", "Transparent Proxy Selector Collision", "HIGH", None, "proxy"),
    # DeFi Specific
    ("ETH-055", "Governance Manipulation", "HIGH", None, "defi"),
    ("ETH-056", "Liquidation Manipulation", "HIGH", None, "defi"),
    ("ETH-057", "Vault Share Inflation / First Depositor", "CRITICAL", None, "defi"),
    ("ETH-058", "Donation Attack", "HIGH", None, "defi"),
    ("ETH-059", "AMM Constant Product Error", "CRITICAL", None, "defi"),
    ("ETH-060", "Missing Transaction Deadline", "MEDIUM", None, "defi"),
    ("ETH-061", "Unrestricted Flash Mint", "HIGH", None, "defi"),
    ("ETH-062", "Pool Imbalance Attack", "HIGH", None, "defi"),
    ("ETH-063", "Reward Distribution Error", "HIGH", None, "defi"),
    ("ETH-064", "Insecure Callback / Hook Handler", "HIGH", None, "defi"),
    ("ETH-065", "Cross-protocol Integration Risk", "MEDIUM", None, "defi"),
    # Gas & DoS
    ("ETH-066", "Unbounded Loop / Array Growth", "HIGH", "SWC-128", "gas-dos"),
    ("ETH-067", "Block Gas Limit DoS", "HIGH", "SWC-128", "gas-dos"),
    ("ETH-068", "Unexpected Revert in Loop", "MEDIUM", "SWC-113", "gas-dos"),
    ("ETH-069", "Griefing Attack", "MEDIUM", None, "gas-dos"),
    ("ETH-070", "Storage Slot Exhaustion", "LOW", None, "gas-dos"),
    # Miscellaneous
    ("ETH-071", "Floating Pragma", "LOW", "SWC-103", "miscellaneous"),
    ("ETH-072", "Outdated Compiler Version", "LOW", "SWC-102", "miscellaneous"),
    ("ETH-073", "Hash Collision with abi.encodePacked", "MEDIUM", "SWC-133", "miscellaneous"),
    ("ETH-074", "Right-to-Left Override Character", "HIGH", "SWC-130", "miscellaneous"),
    ("ETH-075", "Code With No Effects", "LOW", "SWC-135", "miscellaneous"),
    ("ETH-076", "Missing Event Emission", "LOW", None, "miscellaneous"),
    ("ETH-077", "Incorrect Inheritance Order", "MEDIUM", "SWC-125", "miscellaneous"),
    ("ETH-078", "Unencrypted Private Data On-Chain", "LOW", "SWC-136", "miscellaneous"),
    ("ETH-079", "Hardcoded Gas Amount", "LOW", "SWC-134", "miscellaneous"),
    ("ETH-080", "Incorrect Constructor Name (legacy)", "HIGH", "SWC-118", "miscellaneous"),
    # Transient Storage
    ("ETH-081", "Transient Storage Slot Collision", "CRITICAL", None, "transient-storage"),
    ("ETH-082", "Transient Storage Not Cleared", "HIGH", None, "transient-storage"),
    ("ETH-083", "TSTORE Reentrancy Bypass", "CRITICAL", None, "transient-storage"),
    ("ETH-084", "Transient Storage Delegatecall Exposure", "HIGH", None, "transient-storage"),
    ("ETH-085", "Transient Storage Type-Safety Bypass", "MEDIUM", None, "transient-storage"),
    # EIP-7702
    ("ETH-086", "Broken tx.origin == msg.sender Assumption", "CRITICAL", None, "eip-7702"),
    ("ETH-087", "Malicious EIP-7702 Delegation", "HIGH", None, "eip-7702"),
    ("ETH-088", "EIP-7702 Cross-Chain Authorization Replay", "CRITICAL", None, "eip-7702"),
    ("ETH-089", "EOA Code Assumption Failure", "HIGH", None, "eip-7702"),
    # Account Abstraction
    ("ETH-090", "UserOp Hash Collision", "HIGH", None, "account-abstraction"),
    ("ETH-091", "Paymaster Exploitation", "CRITICAL", None, "account-abstraction"),
    ("ETH-092", "Bundler Manipulation", "HIGH", None, "account-abstraction"),
    ("ETH-093", "Validation-Execution Phase Confusion", "CRITICAL", None, "account-abstraction"),
    # Modern DeFi
    ("ETH-094", "Uniswap V4 Hook Callback Authorization", "CRITICAL", None, "modern-defi"),
    ("ETH-095", "Hook Data Manipulation", "HIGH", None, "modern-defi"),
    ("ETH-096", "Cached State Desynchronization", "HIGH", None, "modern-defi"),
    ("ETH-097", "Known Compiler Bug in Used Version", "HIGH", None, "modern-defi"),
    # Input Validation
    ("ETH-098", "Missing Input Validation / Boundary Check", "HIGH", None, "input-validation"),
    ("ETH-099", "Unsafe ABI Decoding / Calldata Manipulation", "HIGH", None, "input-validation"),
    # Off-Chain
    ("ETH-100", "EIP-7702 Delegation Phishing", "CRITICAL", None, "off-chain"),
    ("ETH-101", "Off-Chain Infrastructure Compromise", "CRITICAL", None, "off-chain"),
    # Restaking & L2
    ("ETH-102", "Restaking Cascading Slashing Risk", "HIGH", None, "restaking-l2"),
    ("ETH-103", "L2 Sequencer Dependency", "HIGH", None, "restaking-l2"),
    ("ETH-104", "L2 Cross-Domain Message Replay", "CRITICAL", None, "restaking-l2"),
]

# Tools that can be checked
TOOLS = {
    "slither": {
        "name": "Slither",
        "command": "slither",
        "check_args": ["--version"],
        "install": "pip install slither-analyzer",
        "description": "Static analysis framework (Trail of Bits)",
    },
    "aderyn": {
        "name": "Aderyn",
        "command": "aderyn",
        "check_args": ["--version"],
        "install": "cyfrinup && cyfrinup install aderyn",
        "description": "Fast Rust-based static analyzer (Cyfrin)",
    },
    "mythril": {
        "name": "Mythril",
        "command": "myth",
        "check_args": ["version"],
        "install": "pip install mythril",
        "description": "Symbolic execution engine (ConsenSys)",
    },
    "foundry": {
        "name": "Foundry",
        "command": "forge",
        "check_args": ["--version"],
        "install": "curl -L https://foundry.paradigm.xyz | bash && foundryup",
        "description": "Testing, fuzzing & coverage (Paradigm)",
    },
    "echidna": {
        "name": "Echidna",
        "command": "echidna",
        "check_args": ["--version"],
        "install": "See: github.com/crytic/echidna",
        "description": "Property-based fuzzer (Trail of Bits)",
    },
    "medusa": {
        "name": "Medusa",
        "command": "medusa",
        "check_args": ["--version"],
        "install": "pip install medusa-fuzzer",
        "description": "Coverage-guided parallel fuzzer (Trail of Bits)",
    },
    "halmos": {
        "name": "Halmos",
        "command": "halmos",
        "check_args": ["--version"],
        "install": "pip install halmos",
        "description": "Symbolic testing framework (a16z)",
    },
    "certora": {
        "name": "Certora",
        "command": "certoraRun",
        "check_args": ["--version"],
        "install": "pip install certora-cli",
        "description": "Formal verification with CVL rules",
    },
    "evmbench": {
        "name": "EVMBench",
        "command": "__evmbench_script__",
        "check_args": [],
        "install": "git clone https://github.com/openai/frontier-evals && pip install -e frontier-evals/project/evmbench",
        "description": "Smart contract audit benchmark (OpenAI, 40 audits / 120 vulns)",
    },
}
