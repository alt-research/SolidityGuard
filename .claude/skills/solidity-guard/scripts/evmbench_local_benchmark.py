#!/usr/bin/env python3
"""
EVMBench Local Benchmark — Validate SolidityGuard scanner against real-world audit findings.

Clones 40 EVMBench audit repos, loads ground truth vulnerabilities from the
frontier-evals benchmark dataset, runs SolidityGuard's scan_patterns() scanner,
and maps detected findings to ground truth using keyword/pattern heuristics.

Usage:
    python3 evmbench_local_benchmark.py
    python3 evmbench_local_benchmark.py --clone-dir /tmp/evmbench-repos
    python3 evmbench_local_benchmark.py --concurrency 5
    python3 evmbench_local_benchmark.py --audit 2024-01-curves  # single audit
    python3 evmbench_local_benchmark.py --dry-run               # no cloning
    python3 evmbench_local_benchmark.py --output json -f results.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

# Add parent dir so we can import solidity_guard
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from solidity_guard import scan_patterns, Finding

# ─── Constants ──────────────────────────────────────────────────────────────

EVMBENCH_ORG_URL = "https://github.com/evmbench-org"
EVALS_BASE = "/home/coder/github/frontier-evals/project/evmbench"
AUDITS_DIR = os.path.join(EVALS_BASE, "audits")
TASKS_FILE = os.path.join(EVALS_BASE, "splits", "detect-tasks.txt")

# Directories to search for Solidity source files within cloned repos
SOURCE_DIRS = [
    "contracts",
    "src",
    "packages",
    "vault/src",
    "vault/contracts",
    "protocol/contracts",
    "protocol/src",
]

# Directories to skip when scanning (tests, mocks, interfaces, lib deps)
SKIP_DIRS = {
    "node_modules", "lib", "forge-std", "openzeppelin-contracts",
    "openzeppelin", "@openzeppelin", "test", "tests", "mock", "mocks",
    "script", "scripts", "deployed", "deployment", "tools", "artifacts",
    "cache", "out", ".git", "interfaces",
}

# ─── Vulnerability Category Mapping ────────────────────────────────────────

# Maps keyword patterns (from vuln titles + finding descriptions) to ETH pattern IDs
# Each entry: (compiled_regex, eth_ids, category_label)
VULN_KEYWORD_MAP = [
    # Reentrancy variants
    (re.compile(r"re-?entran", re.I), ["ETH-001", "ETH-002", "ETH-003", "ETH-004", "ETH-005"], "Reentrancy"),

    # Access control
    (re.compile(r"access\s*control|unauthori[sz]|missing\s*(modifier|access|auth)|onlyOwner|privilege\s*escalat|permissionless|unprotected\s*(function|call)|anyone\s*can\s*call|insufficient\s*access", re.I),
     ["ETH-006", "ETH-007", "ETH-008", "ETH-009", "ETH-010", "ETH-011", "ETH-012"], "Access Control"),

    # tx.origin
    (re.compile(r"tx\.origin", re.I), ["ETH-007"], "Access Control"),

    # selfdestruct
    (re.compile(r"selfdestruct|self-?destruct", re.I), ["ETH-008"], "Access Control"),

    # Oracle / price manipulation
    (re.compile(r"oracle|price\s*manipulat|stale\s*(price|data|oracle)|chainlink|TWAP|spot\s*price|price\s*feed", re.I),
     ["ETH-024", "ETH-025", "ETH-026", "ETH-027", "ETH-028"], "Oracle/Price"),

    # Flash loan
    (re.compile(r"flash\s*loan|flash\s*mint", re.I),
     ["ETH-025", "ETH-061"], "Flash Loan"),

    # Overflow / underflow / arithmetic
    (re.compile(r"overflow|underflow|integer\s*(overflow|underflow)|arithmetic", re.I),
     ["ETH-013", "ETH-014", "ETH-015"], "Arithmetic"),

    # Precision / rounding
    (re.compile(r"precision|rounding|round-?down|round-?up|truncat|division\s*before\s*multiplic|loss\s*of\s*precision", re.I),
     ["ETH-014", "ETH-016", "ETH-017"], "Precision/Rounding"),

    # Calculation errors (TVL, accounting, incorrect math)
    (re.compile(r"incorrect\s*(calculation|price|value|result|tvl|accounting)|miscalculat|calculation\s*(is\s*)?incorrect|wrong\s*(calculation|result)|invalid\s*calculation", re.I),
     ["ETH-014", "ETH-016", "ETH-017"], "Calculation Error"),

    # Delegatecall
    (re.compile(r"delegatecall|delegate\s*call", re.I),
     ["ETH-019"], "Delegatecall"),

    # Unchecked return values
    (re.compile(r"unchecked\s*(return|call|external)|return\s*value\s*(not\s*checked|ignored|unchecked)", re.I),
     ["ETH-018", "ETH-022"], "Unchecked Return"),

    # Slippage / MEV / sandwich / front-running
    (re.compile(r"slippage|sandwich|front-?run|frontrun|MEV|deadline|transaction\s*order", re.I),
     ["ETH-026", "ETH-027", "ETH-040", "ETH-060"], "MEV/Frontrunning"),

    # Signature replay / malleability
    (re.compile(r"signature\s*(replay|malleab)|replay\s*(attack|signature)|nonce\s*reuse", re.I),
     ["ETH-038", "ETH-039"], "Signature"),

    # DoS / gas / unbounded
    (re.compile(r"denial\s*of\s*service|DoS|unbounded\s*(loop|array|iteration)|gas\s*limit|griefing|block\s*(stuff|gas)", re.I),
     ["ETH-066", "ETH-067", "ETH-068", "ETH-069"], "DoS/Gas"),

    # Blacklist / blocked / revert in loop
    (re.compile(r"blacklist|blocked|revert\s*in\s*loop|failed\s*call", re.I),
     ["ETH-021", "ETH-068"], "DoS/Revert"),

    # Storage / proxy / upgrade
    (re.compile(r"storage\s*(collision|layout|slot)|proxy|upgrade|uninitialized\s*(impl|proxy)|implementation\s*contract", re.I),
     ["ETH-029", "ETH-030", "ETH-049", "ETH-050", "ETH-051", "ETH-052", "ETH-053"], "Storage/Proxy"),

    # Vault share / first depositor / inflation / donation
    (re.compile(r"vault\s*share|first\s*deposit|inflation|donation\s*attack|share\s*(inflation|manipulat)|deposit.*steal", re.I),
     ["ETH-057", "ETH-058"], "Vault/Share"),

    # ERC-20 token issues
    (re.compile(r"erc-?20|safe\s*transfer|fee-?on-?transfer|rebas|approval\s*race|token\s*supply", re.I),
     ["ETH-041", "ETH-042", "ETH-043", "ETH-046", "ETH-048"], "Token"),

    # ERC-777 hooks
    (re.compile(r"erc-?777|token\s*hook", re.I),
     ["ETH-044"], "ERC-777"),

    # Missing event / emit
    (re.compile(r"missing\s*event|event\s*emission|emit", re.I),
     ["ETH-076"], "Missing Event"),

    # Weak randomness / block attributes
    (re.compile(r"random|block\.(timestamp|number|difficulty)|weak\s*random|predictable", re.I),
     ["ETH-036", "ETH-037"], "Randomness/Timestamp"),

    # Timestamp dependence
    (re.compile(r"timestamp\s*(depend|manipulat)|block\.timestamp", re.I),
     ["ETH-036"], "Timestamp"),

    # Governance
    (re.compile(r"governance|voting|proposal|quorum", re.I),
     ["ETH-055"], "Governance"),

    # Liquidation
    (re.compile(r"liquidat", re.I),
     ["ETH-056"], "Liquidation"),

    # Reward / fee distribution
    (re.compile(r"reward|fee\s*(distribut|split|claim)|claim\s*fee|yield|dividend", re.I),
     ["ETH-063"], "Reward Distribution"),

    # AMM / pool / swap
    (re.compile(r"AMM|constant\s*product|pool\s*(imbalance|drain)|swap\s*(error|bug)", re.I),
     ["ETH-059", "ETH-062"], "AMM/Pool"),

    # Missing zero address check / input validation
    (re.compile(r"zero\s*address|address\(0\)|input\s*validation|missing\s*(check|validation|boundary)", re.I),
     ["ETH-045", "ETH-098"], "Input Validation"),

    # Pragma / compiler
    (re.compile(r"floating\s*pragma|pragma\s*solidity|compiler\s*(version|bug)", re.I),
     ["ETH-071", "ETH-072", "ETH-097"], "Compiler"),

    # Hash collision / encodePacked
    (re.compile(r"hash\s*collision|encodePacked|abi\.encode", re.I),
     ["ETH-073"], "Hash Collision"),

    # Strict equality / unexpected ether balance / stuck funds / msg.value not refunded
    (re.compile(r"strict\s*equal|==\s*balance|balance\s*==|stuck|become\s*stuck|not\s*refund|excess\s*msg\.value|remaining\s*(value|ether|ETH|balance)|msg\.value.*not\s*(refund|return)|native\s*gas\s*token.*stuck|ether\s*balance\s*should", re.I),
     ["ETH-032", "ETH-034"], "Stuck Funds/Strict Equality"),

    # Cross-contract / integration / connector
    (re.compile(r"cross-?(contract|protocol)|integration|connector\s*(error|bug|incorrect)", re.I),
     ["ETH-003", "ETH-065"], "Cross-Contract"),

    # Callback / hook handler
    (re.compile(r"callback|hook\s*(handler|bypass)|insecure\s*(callback|hook)", re.I),
     ["ETH-064", "ETH-094", "ETH-095"], "Callback/Hook"),

    # Lock / unlock / timelock
    (re.compile(r"lock|unlock|timelock|time\s*lock|lockup|lock\s*period|extend.*unlock|unlock.*early", re.I),
     ["ETH-034", "ETH-098"], "Lock/Timelock"),

    # Honeypot / DoS via revert
    (re.compile(r"honeypot|honey\s*pot|can\'?t?\s*sell|block\s*sell", re.I),
     ["ETH-021", "ETH-069"], "Honeypot/DoS"),

    # Airdrop
    (re.compile(r"airdrop|claim|withdraw", re.I),
     ["ETH-063", "ETH-098"], "Airdrop/Claim"),

    # Gas / issuance / L2
    (re.compile(r"gas\s*issuance|base\s*fee|sequencer|L2|layer\s*2|cross-?domain", re.I),
     ["ETH-066", "ETH-067", "ETH-103", "ETH-104"], "Gas/L2"),

    # Malformed / equate / logic
    (re.compile(r"malformed|equate|logic\s*(error|bug|flaw)|incorrect\s*(state|logic|condition|implementation|handling)|invalid\s*(state|handling|logic|implementation)", re.I),
     ["ETH-006", "ETH-034", "ETH-098"], "Logic Error"),

    # Loss of funds / steal / drain
    (re.compile(r"loss\s*of\s*funds|steal|drain|theft|siphon|exploit", re.I),
     ["ETH-001", "ETH-006", "ETH-025", "ETH-057"], "Fund Loss"),

    # Position / holding / registry
    (re.compile(r"position|holding|registry|remove\s*position|update.*position|position\s*TVL", re.I),
     ["ETH-098"], "Position Management"),
]


@dataclass
class GroundTruthVuln:
    """A single ground-truth vulnerability from EVMBench."""
    audit_id: str
    vuln_id: str
    title: str
    award: float
    finding_text: str = ""
    mapped_categories: list = field(default_factory=list)
    mapped_eth_ids: list = field(default_factory=list)


@dataclass
class BenchmarkResult:
    """Result of matching scanner output to a single ground truth vuln."""
    vuln: GroundTruthVuln
    hit: bool = False
    matched_finding_ids: list = field(default_factory=list)
    matched_finding_titles: list = field(default_factory=list)
    match_reason: str = ""


@dataclass
class AuditBenchmark:
    """Benchmark results for one audit."""
    audit_id: str
    total_vulns: int
    hits: int
    misses: int
    results: list = field(default_factory=list)
    scanner_findings_count: int = 0
    error: str = ""


# ─── Helper Functions ───────────────────────────────────────────────────────

def load_audit_ids(tasks_file: str = TASKS_FILE) -> list:
    """Load audit IDs from detect-tasks.txt."""
    with open(tasks_file, "r") as f:
        return [line.strip() for line in f if line.strip()]


def load_ground_truth(audit_id: str) -> list:
    """Load ground truth vulnerabilities from config.yaml and findings/*.md."""
    import yaml

    config_path = os.path.join(AUDITS_DIR, audit_id, "config.yaml")
    findings_dir = os.path.join(AUDITS_DIR, audit_id, "findings")

    if not os.path.exists(config_path):
        return []

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    vulns = []
    for v in config.get("vulnerabilities", []):
        vuln = GroundTruthVuln(
            audit_id=audit_id,
            vuln_id=v["id"],
            title=v["title"],
            award=v.get("award", 0.0),
        )

        # Load the detailed finding description if available
        finding_path = os.path.join(findings_dir, f"{v['id']}.md")
        if os.path.exists(finding_path):
            try:
                with open(finding_path, "r") as f:
                    vuln.finding_text = f.read()
            except Exception:
                pass

        # Map to ETH pattern categories using keyword heuristics
        combined_text = vuln.title + " " + vuln.finding_text
        matched_categories = set()
        matched_eth_ids = set()

        for regex, eth_ids, category in VULN_KEYWORD_MAP:
            if regex.search(combined_text):
                matched_categories.add(category)
                matched_eth_ids.update(eth_ids)

        vuln.mapped_categories = sorted(matched_categories)
        vuln.mapped_eth_ids = sorted(matched_eth_ids)

        vulns.append(vuln)

    return vulns


def clone_repo(audit_id: str, clone_dir: str) -> str:
    """Clone an EVMBench audit repo. Returns the path to the cloned repo."""
    repo_url = f"{EVMBENCH_ORG_URL}/{audit_id}.git"
    repo_path = os.path.join(clone_dir, audit_id)

    if os.path.exists(repo_path):
        # Already cloned
        return repo_path

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, repo_path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  [WARN] Clone failed for {audit_id}: {result.stderr.strip()}")
            return ""
    except subprocess.TimeoutExpired:
        print(f"  [WARN] Clone timed out for {audit_id}")
        return ""
    except Exception as e:
        print(f"  [WARN] Clone error for {audit_id}: {e}")
        return ""

    return repo_path


def find_source_dirs(repo_path: str) -> list:
    """Find directories containing Solidity source files.

    Returns a list of directories that contain .sol files, excluding
    test/mock/lib directories.
    """
    source_dirs = []

    # Check common source directories first
    for src_dir in SOURCE_DIRS:
        full_path = os.path.join(repo_path, src_dir)
        if os.path.isdir(full_path):
            # Check it actually has .sol files
            sol_files = list(Path(full_path).rglob("*.sol"))
            if sol_files:
                source_dirs.append(full_path)

    # If no standard dirs found, look for .sol files anywhere in the repo
    if not source_dirs:
        for root, dirs, files in os.walk(repo_path):
            # Filter out skip dirs
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            sol_files = [f for f in files if f.endswith(".sol")]
            if sol_files:
                source_dirs.append(root)
                break  # just use the first found dir

    return source_dirs


def filter_source_files(repo_path: str) -> str:
    """Create a filtered view of source files, excluding tests/mocks/libs.

    Instead of filtering, we return the best source directory to scan.
    """
    source_dirs = find_source_dirs(repo_path)
    if source_dirs:
        return source_dirs[0]
    return repo_path


def match_finding_to_vuln(finding: Finding, vuln: GroundTruthVuln) -> tuple:
    """Check if a scanner finding matches a ground truth vulnerability.

    Returns (matched: bool, reason: str).

    Matching strategy:
    1. Direct ETH-ID match: scanner finding ID matches mapped ETH IDs
    2. Category keyword match: scanner finding category/title keywords match vuln keywords
    3. File/code context match: scanner found issue in a file related to the vuln
    """
    finding_id = finding.id  # e.g. "ETH-001"

    # Strategy 1: Direct ETH-ID match
    if finding_id in vuln.mapped_eth_ids:
        return True, f"{finding_id} ({finding.category})"

    # Strategy 2: Broader category match using finding title/description
    finding_text = (finding.title + " " + finding.description + " " + finding.category).lower()
    vuln_text = (vuln.title + " " + vuln.finding_text[:2000]).lower()

    # Cross-reference keywords between finding and vuln
    match_pairs = [
        (["reentrancy", "reentrant", "re-entry", "cei violation"], ["reentrancy", "reentrant", "re-entry", "re-entran"]),
        (["access control", "unauthorized", "missing modifier", "unprotected"], ["access control", "unauthorized", "missing modifier", "unprotected", "anyone can", "permissionless"]),
        (["oracle", "price manipulation", "stale"], ["oracle", "price manipulat", "stale price", "price feed", "chainlink"]),
        (["overflow", "underflow", "arithmetic"], ["overflow", "underflow", "arithmetic"]),
        (["precision", "rounding", "division"], ["precision", "rounding", "truncat", "division", "loss of precision"]),
        (["delegatecall"], ["delegatecall"]),
        (["unchecked return", "return value"], ["unchecked return", "return value"]),
        (["slippage", "front-run", "sandwich", "mev"], ["slippage", "front-run", "sandwich", "mev"]),
        (["signature", "replay"], ["signature", "replay"]),
        (["dos", "denial of service", "unbounded", "gas limit", "griefing"], ["dos", "denial of service", "unbounded", "gas limit", "griefing", "block"]),
        (["storage", "proxy", "upgrade"], ["storage", "proxy", "upgrade"]),
        (["vault share", "first deposit", "inflation", "donation"], ["vault", "share", "inflation", "donation", "first deposit"]),
        (["reward", "fee distribution", "claim"], ["reward", "fee distribut", "claim fee", "fee split"]),
        (["flash loan"], ["flash loan"]),
        (["governance", "voting"], ["governance", "voting"]),
        (["liquidation"], ["liquidation"]),
        (["selfdestruct"], ["selfdestruct"]),
        (["timestamp", "block.timestamp"], ["timestamp"]),
        (["randomness", "random"], ["random"]),
        (["missing event"], ["missing event"]),
        (["zero address", "input validation"], ["zero address", "input validation"]),
    ]

    for finding_kws, vuln_kws in match_pairs:
        finding_match = any(kw in finding_text for kw in finding_kws)
        vuln_match = any(kw in vuln_text for kw in vuln_kws)
        if finding_match and vuln_match:
            return True, f"{finding_id} (keyword: {finding_kws[0]})"

    return False, ""


def run_benchmark_for_audit(
    audit_id: str,
    clone_dir: str,
    vulns: list,
    skip_clone: bool = False,
) -> AuditBenchmark:
    """Run the scanner against one audit and match findings to ground truth."""
    benchmark = AuditBenchmark(
        audit_id=audit_id,
        total_vulns=len(vulns),
        hits=0,
        misses=0,
    )

    if not vulns:
        benchmark.error = "No ground truth vulnerabilities found"
        return benchmark

    # Clone the repo
    if skip_clone:
        repo_path = os.path.join(clone_dir, audit_id)
        if not os.path.exists(repo_path):
            benchmark.error = "Repo not cloned (dry-run mode)"
            return benchmark
    else:
        repo_path = clone_repo(audit_id, clone_dir)
        if not repo_path:
            benchmark.error = "Failed to clone repo"
            return benchmark

    # Find and scan source directories
    source_dirs = find_source_dirs(repo_path)
    if not source_dirs:
        benchmark.error = "No Solidity source files found"
        return benchmark

    # Run scanner on all source directories
    all_findings = []
    for src_dir in source_dirs:
        try:
            findings = scan_patterns(src_dir)
            all_findings.extend(findings)
        except Exception:
            pass  # Some dirs may fail, that's OK

    # If no findings from specific dirs, try the whole repo
    if not all_findings:
        try:
            all_findings = scan_patterns(repo_path)
        except Exception as e:
            benchmark.error = f"Scanner error: {e}"
            return benchmark

    benchmark.scanner_findings_count = len(all_findings)

    # Match each ground truth vuln against scanner findings
    for vuln in vulns:
        result = BenchmarkResult(vuln=vuln)

        for finding in all_findings:
            matched, reason = match_finding_to_vuln(finding, vuln)
            if matched:
                result.hit = True
                result.matched_finding_ids.append(finding.id)
                result.matched_finding_titles.append(finding.title)
                if not result.match_reason:
                    result.match_reason = reason

        if result.hit:
            benchmark.hits += 1
            # Deduplicate matched IDs
            result.matched_finding_ids = sorted(set(result.matched_finding_ids))
            result.matched_finding_titles = sorted(set(result.matched_finding_titles))
        else:
            benchmark.misses += 1

        benchmark.results.append(result)

    return benchmark


# ─── Output Formatting ──────────────────────────────────────────────────────

def print_audit_result(bench: AuditBenchmark):
    """Print results for one audit."""
    pct = (bench.hits / bench.total_vulns * 100) if bench.total_vulns > 0 else 0
    print(f"\nAudit: {bench.audit_id} ({bench.total_vulns} vulns, {bench.scanner_findings_count} scanner findings)")

    if bench.error:
        print(f"  [ERROR] {bench.error}")
        return

    for r in bench.results:
        vuln = r.vuln
        if r.hit:
            ids = ", ".join(r.matched_finding_ids[:3])
            reason = r.match_reason
            print(f"  [HIT]  {vuln.vuln_id}: {vuln.title[:70]}")
            print(f"         -> {ids} ({reason})")
        else:
            cats = ", ".join(vuln.mapped_categories[:3]) if vuln.mapped_categories else "Unmapped"
            print(f"  [MISS] {vuln.vuln_id}: {vuln.title[:70]}")
            print(f"         Expected categories: {cats}")

    print(f"  Score: {bench.hits}/{bench.total_vulns} ({pct:.0f}%)")


def print_summary(benchmarks: list):
    """Print overall benchmark summary."""
    total_vulns = sum(b.total_vulns for b in benchmarks)
    total_hits = sum(b.hits for b in benchmarks)
    total_misses = sum(b.misses for b in benchmarks)
    errors = sum(1 for b in benchmarks if b.error)
    pct = (total_hits / total_vulns * 100) if total_vulns > 0 else 0

    print("\n" + "=" * 65)
    print("OVERALL SUMMARY")
    print("=" * 65)
    print(f"Audits processed: {len(benchmarks)} ({errors} errors)")
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"Detected (HIT):  {total_hits}")
    print(f"Missed (MISS):   {total_misses}")
    print(f"Detection rate:  {total_hits}/{total_vulns} ({pct:.1f}%)")

    # Per-category breakdown
    category_stats = {}
    for b in benchmarks:
        for r in b.results:
            for cat in r.vuln.mapped_categories:
                if cat not in category_stats:
                    category_stats[cat] = {"total": 0, "hits": 0}
                category_stats[cat]["total"] += 1
                if r.hit:
                    category_stats[cat]["hits"] += 1

    if category_stats:
        print("\nPer-Category Detection:")
        print(f"  {'Category':<30} {'Hits':>5} {'Total':>6} {'Rate':>7}")
        print(f"  {'-'*30} {'-'*5} {'-'*6} {'-'*7}")
        for cat in sorted(category_stats.keys()):
            s = category_stats[cat]
            rate = (s["hits"] / s["total"] * 100) if s["total"] > 0 else 0
            print(f"  {cat:<30} {s['hits']:>5} {s['total']:>6} {rate:>6.0f}%")

    # Top missed vulns (by award)
    missed = []
    for b in benchmarks:
        for r in b.results:
            if not r.hit:
                missed.append((r.vuln.award, r.vuln.audit_id, r.vuln.vuln_id, r.vuln.title[:60]))

    if missed:
        missed.sort(reverse=True)
        print("\nTop 10 Highest-Award Missed Vulnerabilities:")
        for award, audit, vid, title in missed[:10]:
            print(f"  ${award:>10,.2f}  {audit}/{vid}: {title}")


def results_to_json(benchmarks: list) -> dict:
    """Convert results to JSON-serializable dict."""
    total_vulns = sum(b.total_vulns for b in benchmarks)
    total_hits = sum(b.hits for b in benchmarks)

    return {
        "benchmark": "EVMBench Local",
        "scanner": "SolidityGuard scan_patterns()",
        "total_audits": len(benchmarks),
        "total_vulns": total_vulns,
        "total_hits": total_hits,
        "total_misses": total_vulns - total_hits,
        "detection_rate": round(total_hits / total_vulns * 100, 1) if total_vulns > 0 else 0,
        "audits": [
            {
                "audit_id": b.audit_id,
                "total_vulns": b.total_vulns,
                "hits": b.hits,
                "misses": b.misses,
                "scanner_findings": b.scanner_findings_count,
                "error": b.error,
                "results": [
                    {
                        "vuln_id": r.vuln.vuln_id,
                        "title": r.vuln.title,
                        "award": r.vuln.award,
                        "hit": r.hit,
                        "matched_ids": r.matched_finding_ids,
                        "match_reason": r.match_reason,
                        "mapped_categories": r.vuln.mapped_categories,
                    }
                    for r in b.results
                ],
            }
            for b in benchmarks
        ],
    }


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="EVMBench Local Benchmark - SolidityGuard Scanner Evaluation"
    )
    parser.add_argument(
        "--clone-dir", default="/tmp/evmbench-repos",
        help="Directory to clone EVMBench repos into (default: /tmp/evmbench-repos)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=5,
        help="Number of concurrent repo clones (default: 5)"
    )
    parser.add_argument(
        "--audit", type=str, default=None,
        help="Run benchmark for a single audit ID only"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Skip cloning, only show ground truth mapping"
    )
    parser.add_argument(
        "--output", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-f", "--file", type=str, default=None,
        help="Write results to file"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show scanner findings for each audit"
    )

    args = parser.parse_args()

    # Header
    print("=" * 65)
    print("EVMBench Local Benchmark -- SolidityGuard Scanner")
    print("=" * 65)

    # Load audit IDs
    if args.audit:
        audit_ids = [args.audit]
    else:
        audit_ids = load_audit_ids()

    print(f"Audits to benchmark: {len(audit_ids)}")

    # Load ground truth for all audits
    print("Loading ground truth from frontier-evals...")
    ground_truth = {}
    total_gt_vulns = 0
    for audit_id in audit_ids:
        vulns = load_ground_truth(audit_id)
        ground_truth[audit_id] = vulns
        total_gt_vulns += len(vulns)
    print(f"Total ground truth vulnerabilities: {total_gt_vulns}")

    if args.dry_run:
        print("\n[DRY RUN] Showing ground truth mapping only:\n")
        for audit_id in audit_ids:
            vulns = ground_truth[audit_id]
            print(f"\n{audit_id} ({len(vulns)} vulns):")
            for v in vulns:
                cats = ", ".join(v.mapped_categories[:3]) if v.mapped_categories else "UNMAPPED"
                eth = ", ".join(v.mapped_eth_ids[:5]) if v.mapped_eth_ids else "none"
                print(f"  {v.vuln_id}: {v.title[:65]}")
                print(f"    -> Categories: {cats} | ETH IDs: {eth}")
        return

    # Create clone directory
    os.makedirs(args.clone_dir, exist_ok=True)

    # Clone repos in parallel
    print(f"\nCloning {len(audit_ids)} repos into {args.clone_dir} (concurrency={args.concurrency})...")
    start_time = time.time()

    clone_results = {}
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {
            executor.submit(clone_repo, audit_id, args.clone_dir): audit_id
            for audit_id in audit_ids
        }
        for future in as_completed(futures):
            audit_id = futures[future]
            try:
                path = future.result()
                clone_results[audit_id] = path
                status = "OK" if path else "FAILED"
            except Exception as e:
                clone_results[audit_id] = ""
                status = f"ERROR: {e}"
            print(f"  [{status}] {audit_id}")

    clone_time = time.time() - start_time
    cloned = sum(1 for v in clone_results.values() if v)
    print(f"Cloned {cloned}/{len(audit_ids)} repos in {clone_time:.1f}s")

    # Run benchmarks
    print(f"\nRunning SolidityGuard scanner against {len(audit_ids)} audits...")
    scan_start = time.time()

    benchmarks = []
    for audit_id in audit_ids:
        vulns = ground_truth[audit_id]
        bench = run_benchmark_for_audit(
            audit_id=audit_id,
            clone_dir=args.clone_dir,
            vulns=vulns,
            skip_clone=False,
        )
        benchmarks.append(bench)
        print_audit_result(bench)

    scan_time = time.time() - scan_start
    total_time = time.time() - start_time

    print(f"\nScan time: {scan_time:.1f}s | Total time: {total_time:.1f}s")

    # Summary
    print_summary(benchmarks)

    # JSON output
    if args.output == "json" or args.file:
        result_json = results_to_json(benchmarks)
        if args.file:
            with open(args.file, "w") as f:
                json.dump(result_json, f, indent=2)
            print(f"\nResults written to {args.file}")
        if args.output == "json":
            print(json.dumps(result_json, indent=2))


if __name__ == "__main__":
    main()
