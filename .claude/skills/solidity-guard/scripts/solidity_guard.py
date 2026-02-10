#!/usr/bin/env python3
"""
SolidityGuard - Combined Scanner Orchestrator

Orchestrates Slither, Aderyn, and manual pattern detection for comprehensive
Solidity smart contract security analysis. Aggregates findings with confidence
scoring from multiple sources.

Usage:
    python3 solidity_guard.py ./contracts
    python3 solidity_guard.py ./contracts --output json -f results.json
    python3 solidity_guard.py ./contracts --tools slither,aderyn
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: float
    file: str
    line: int
    code_snippet: str
    description: str
    recommendation: str
    category: str
    swc: Optional[str] = None
    tool: str = "manual"

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResults:
    project: str
    timestamp: str
    tools_used: list
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    security_score: int = 100

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def calculate_score(self):
        critical = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        medium = sum(1 for f in self.findings if f.severity == "MEDIUM")
        low = sum(1 for f in self.findings if f.severity == "LOW")
        info = sum(1 for f in self.findings if f.severity == "INFORMATIONAL")

        self.security_score = max(0, 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1))
        self.summary = {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "informational": info,
            "total": len(self.findings),
            "security_score": self.security_score,
        }

    def to_dict(self):
        return {
            "project": self.project,
            "timestamp": self.timestamp,
            "tools_used": self.tools_used,
            "summary": self.summary,
            "security_score": self.security_score,
            "findings": [f.to_dict() for f in self.findings],
        }


def run_slither(target_path: str) -> list:
    """Run Slither static analysis and parse results."""
    findings = []
    try:
        result = subprocess.run(
            ["slither", target_path, "--json", "-"],
            capture_output=True, text=True, timeout=300
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for detector in data.get("results", {}).get("detectors", []):
                severity_map = {
                    "High": "HIGH",
                    "Medium": "MEDIUM",
                    "Low": "LOW",
                    "Informational": "INFORMATIONAL",
                }
                confidence_map = {
                    "High": 0.85,
                    "Medium": 0.70,
                    "Low": 0.55,
                }
                elements = detector.get("elements", [])
                file_path = ""
                line_num = 0
                snippet = ""
                if elements:
                    src = elements[0].get("source_mapping", {})
                    file_path = src.get("filename_relative", "unknown")
                    line_num = src.get("lines", [0])[0] if src.get("lines") else 0
                    snippet = elements[0].get("name", "")

                findings.append(Finding(
                    id=f"SLITHER-{detector.get('check', 'unknown')}",
                    title=detector.get("check", "Unknown").replace("-", " ").title(),
                    severity=severity_map.get(detector.get("impact", ""), "INFORMATIONAL"),
                    confidence=confidence_map.get(detector.get("confidence", ""), 0.60),
                    file=file_path,
                    line=line_num,
                    code_snippet=snippet,
                    description=detector.get("description", ""),
                    recommendation=detector.get("markdown", ""),
                    category=detector.get("check", "unknown"),
                    tool="slither",
                ))
    except FileNotFoundError:
        print("[WARN] Slither not installed. Install with: pip install slither-analyzer")
    except subprocess.TimeoutExpired:
        print("[WARN] Slither timed out after 300s")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[WARN] Failed to parse Slither output: {e}")

    return findings


def run_aderyn(target_path: str) -> list:
    """Run Aderyn static analysis and parse results."""
    findings = []
    try:
        subprocess.run(
            ["aderyn", "-s", target_path, "-o", "/tmp/aderyn_output.md"],
            capture_output=True, text=True, timeout=120
        )
        # Parse markdown output
        if os.path.exists("/tmp/aderyn_output.md"):
            with open("/tmp/aderyn_output.md") as f:
                content = f.read()
            # Basic parsing of Aderyn markdown report
            if "High" in content or "Medium" in content:
                findings.append(Finding(
                    id="ADERYN-report",
                    title="Aderyn Analysis Complete",
                    severity="INFORMATIONAL",
                    confidence=0.75,
                    file="",
                    line=0,
                    code_snippet="",
                    description="Aderyn report generated at /tmp/aderyn_output.md",
                    recommendation="Review /tmp/aderyn_output.md for detailed findings",
                    category="aderyn-report",
                    tool="aderyn",
                ))
    except FileNotFoundError:
        print("[WARN] Aderyn not installed. Install with: cyfrinup")
    except subprocess.TimeoutExpired:
        print("[WARN] Aderyn timed out after 120s")

    return findings


def scan_patterns(target_path: str) -> list:
    """Enhanced regex-based pattern scanning for 45+ vulnerability patterns."""
    import re
    findings = []
    sol_files = list(Path(target_path).rglob("*.sol"))

    def _add(fid, title, sev, conf, fpath, ln, snip, desc, rec, cat, swc=None):
        findings.append(Finding(
            id=fid, title=title, severity=sev, confidence=conf,
            file=str(fpath), line=ln, code_snippet=snip.strip(),
            description=desc, recommendation=rec, category=cat,
            swc=swc, tool="pattern-scanner",
        ))

    for sol_file in sol_files:
        try:
            content = sol_file.read_text()
            lines = content.split("\n")
        except Exception:
            continue

        # ─── File-level context flags ────────────────────────────────
        cl = content.lower()
        # Only count SafeERC20 if it's actually USED (not just imported)
        has_safe_erc20_usage = "safetransfer(" in cl or "safetransferfrom(" in cl
        has_reentrancy_guard = "nonreentrant" in cl or "reentrancyguard" in cl
        has_chainid = "block.chainid" in cl or "chainid" in cl
        has_safemath = "using safemath for" in cl

        # Detect pragma version
        pragma_m = re.search(r'pragma solidity\s*[\^>=<~]*\s*(0\.(\d+)\.(\d+))', content)
        pragma_ver = pragma_m.group(1) if pragma_m else "0.8.20"
        pragma_minor = int(pragma_m.group(2)) if pragma_m else 8
        pragma_patch = int(pragma_m.group(3)) if pragma_m else 20
        is_old_pragma = pragma_minor < 8  # < 0.8.0
        is_dirty_bytes_ver = pragma_minor == 8 and pragma_patch < 15  # 0.8.0-0.8.14

        # Track emitted finding IDs per file to avoid duplicates
        file_findings = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue  # skip comments

            # ─── ETH-001: Reentrancy (CEI violation) ────────────────
            if ".call{value:" in line or ".call{ value:" in line:
                # Check for nonReentrant in LOCAL function scope (not file-level)
                local_has_guard = False
                for j in range(max(1, i - 5), i):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if "nonreentrant" in ctx.lower() or "nonReentrant" in ctx:
                        local_has_guard = True
                        break
                if not local_has_guard and "ETH-001" not in file_findings:
                    for j in range(i + 1, min(i + 20, len(lines) + 1)):
                        ctx = lines[j - 1]
                        if ctx.strip().startswith("//"):
                            continue
                        # Broad match: state update after external call (CEI violation)
                        # Matches: balances[x] -= y, mapping[x] = y, state -= val, etc.
                        if re.search(r'\w+\[.*?\]\s*[-+*]?=\s', ctx) or \
                           re.search(r'balance\w*\s*[-+]?=', ctx) or \
                           re.search(r'\b(state|total|amount|counter|balance)\w*\s*[-+]?=', ctx):
                            _add("ETH-001", "Single-function Reentrancy (CEI Violation)", "CRITICAL", 0.85,
                                 sol_file, i, stripped,
                                 "External call with value transfer before state update. Classic reentrancy via CEI violation.",
                                 "Follow Checks-Effects-Interactions: update state before external call. Use ReentrancyGuard.",
                                 "reentrancy", "SWC-107")
                            file_findings.add("ETH-001")
                            break

            # ─── ETH-004: Read-only Reentrancy ─────────────────────
            # Detect: view function depending on external state (e.g. pool.get_virtual_price())
            # combined with receive()/fallback() calling that view function
            if "ETH-004" not in file_findings:
                if ("receive()" in line or "fallback()" in line) and "external" in line:
                    # Check if callback body calls a target/view function
                    for j in range(i, min(i + 15, len(lines) + 1)):
                        ctx = lines[j - 1]
                        if re.search(r'\b(target|vuln|victim)\w*\.\w+\(', ctx, re.IGNORECASE) or \
                           "get_virtual_price" in ctx or "getReward" in ctx:
                            _add("ETH-004", "Read-only Reentrancy Risk", "HIGH", 0.70,
                                 sol_file, i, stripped,
                                 "Callback (receive/fallback) reads external state during reentrancy window.",
                                 "Use reentrancy-aware oracles or check reentrancy lock in view functions.",
                                 "reentrancy")
                            file_findings.add("ETH-004")
                            break
                # Also: view function using external price in same file as external call
                if "view" in line and "function" in line and ("external" in line or "public" in line):
                    if ("get_virtual_price" in cl or "getprice" in cl) and \
                       ("remove_liquidity" in cl or "receive()" in cl):
                        _add("ETH-004", "Read-only Reentrancy Risk", "HIGH", 0.65,
                             sol_file, i, stripped,
                             "View function returns state dependent on external oracle, exploitable during reentrancy.",
                             "Use reentrancy-aware oracles or check reentrancy lock in view functions.",
                             "reentrancy")
                        file_findings.add("ETH-004")

            # ─── ETH-006: Missing Access Control ───────────────────
            if "function" in line and ("external" in line or "public" in line):
                func_m = re.search(r'function\s+(\w+)', line)
                if func_m:
                    fname = func_m.group(1).lower()
                    sensitive = ["owner", "admin", "mint", "burn", "withdraw", "recover",
                                 "upgrade", "pause", "unpause", "kill", "destroy", "set",
                                 "change", "remove", "delete", "transfer"]
                    is_sensitive = any(s in fname for s in sensitive)
                    has_modifier = any(m in line for m in [
                        "onlyOwner", "onlyAdmin", "onlyRole", "only", "auth",
                        "restricted", "whenNotPaused", "initializer", "nonReentrant",
                        "modifier"])
                    # Check for state writes in next 5 lines
                    if is_sensitive and not has_modifier:
                        has_state_write = False
                        for j in range(i, min(i + 6, len(lines) + 1)):
                            ctx = lines[j - 1]
                            if re.search(r'\b\w+\s*=\s*[^=]', ctx) and "==" not in ctx and "!=" not in ctx:
                                has_state_write = True
                                break
                        if has_state_write:
                            _add("ETH-006", "Missing Access Control on Sensitive Function", "CRITICAL", 0.70,
                                 sol_file, i, stripped,
                                 f"Function '{func_m.group(1)}' modifies state without access control modifier.",
                                 "Add onlyOwner, onlyRole, or similar access control modifier.",
                                 "access-control", "SWC-105")

            # ─── ETH-007: tx.origin ────────────────────────────────
            if "tx.origin" in line and ("require" in line or "if" in line):
                _add("ETH-007", "tx.origin Authentication", "CRITICAL", 0.90,
                     sol_file, i, stripped,
                     "tx.origin used for authentication. Vulnerable to phishing via intermediate contracts.",
                     "Replace tx.origin with msg.sender for authentication.",
                     "access-control", "SWC-115")

            # ─── ETH-008: selfdestruct ─────────────────────────────
            if "selfdestruct" in line or "suicide" in line:
                _add("ETH-008", "selfdestruct Usage", "HIGH", 0.75,
                     sol_file, i, stripped,
                     "selfdestruct found. Check access control and proxy implications.",
                     "Ensure selfdestruct has proper access control. Consider removing if not needed.",
                     "access-control", "SWC-106")

            # ─── ETH-009: Default Visibility / Missing modifier ────
            if "function" in line and ("public" in line or "external" in line):
                func_m = re.search(r'function\s+(\w+)', line)
                if func_m:
                    fname = func_m.group(1).lower()
                    owner_funcs = ["changeowner", "setowner", "transferownership", "updateowner"]
                    if fname in owner_funcs:
                        has_mod = any(m in line for m in ["onlyOwner", "only", "auth"])
                        if not has_mod:
                            _add("ETH-009", "Unprotected Ownership Function", "CRITICAL", 0.85,
                                 sol_file, i, stripped,
                                 "Ownership change function accessible without access control.",
                                 "Add onlyOwner modifier to restrict access.",
                                 "access-control", "SWC-100")

            # ─── ETH-012: Hidden Backdoor via Assembly ─────────────
            if "sstore" in line and ("assembly" in cl):
                _add("ETH-012", "Assembly sstore — Potential Backdoor", "HIGH", 0.65,
                     sol_file, i, stripped,
                     "Direct storage write via assembly sstore. May indicate backdoor or hidden state manipulation.",
                     "Review assembly sstore usage. Ensure no unauthorized storage modifications.",
                     "access-control")

            # ─── ETH-013: Unchecked Arithmetic ─────────────────────
            if "unchecked" in line and "{" in line:
                _add("ETH-013", "Unchecked Arithmetic Block", "HIGH", 0.70,
                     sol_file, i, stripped,
                     "unchecked block disables overflow/underflow protection.",
                     "Ensure values in unchecked blocks cannot overflow. Add bounds checks.",
                     "arithmetic", "SWC-101")

            # ETH-013 variant: old pragma (< 0.8.0) arithmetic without SafeMath
            if is_old_pragma and not has_safemath and "ETH-013-old" not in file_findings:
                # Match: x -= y, x += y, mapping[k] -= y, x = a + b, etc.
                if re.search(r'[\w\]]\s*[-+\*]=\s*\w', line) or re.search(r'\w+\s*=\s*\w+\s*[-+\*]\s*\w', line):
                    if "function" not in line and "pragma" not in line and "import" not in line and "event" not in line:
                        _add("ETH-013", "Arithmetic Without Overflow Protection (pre-0.8.0)", "HIGH", 0.80,
                             sol_file, i, stripped,
                             f"Solidity {pragma_ver} lacks automatic overflow checks. No SafeMath detected.",
                             "Upgrade to Solidity >= 0.8.0 or use OpenZeppelin SafeMath library.",
                             "arithmetic", "SWC-101")
                        file_findings.add("ETH-013-old")

            # ETH-013 variant: unsafe downcast (uint8(amount), uint16(...), etc.)
            downcast_m = re.search(r'\buint(8|16|32|64|128)\s*\(', line)
            if downcast_m and "function" not in line and "event" not in line and "error" not in line:
                _add("ETH-013", "Unsafe Integer Downcast", "HIGH", 0.70,
                     sol_file, i, stripped,
                     f"Unsafe downcast to uint{downcast_m.group(1)} may silently truncate larger values.",
                     "Use OpenZeppelin SafeCast library or validate value fits in target type.",
                     "arithmetic", "SWC-101")

            # ─── ETH-014: Division Before Multiplication ───────────
            # Match: a / b * c  OR  (a / b) * c  OR  (price / 100) * discount
            if re.search(r'[\w\)]\s*/\s*[\w\(]+[\w\)]\s*\)\s*\*\s*\w+', line) or \
               re.search(r'\b\w+\s*/\s*\w+\s*\*\s*\w+', line):
                if "//" not in stripped[:2] and "/*" not in stripped[:2]:
                    _add("ETH-014", "Division Before Multiplication", "MEDIUM", 0.70,
                         sol_file, i, stripped,
                         "Division before multiplication causes precision loss due to integer truncation.",
                         "Reorder to multiply first: (a * c) / b instead of (a / b) * c.",
                         "arithmetic")

            # ─── ETH-017: Precision Loss ───────────────────────────
            # Detect: division by large denominators (1e18, 365 days, etc.) or division yielding 0
            if re.search(r'/\s*\(?\s*(?:\d+\s*(?:days|hours|minutes|seconds)\s*\*\s*1e\d+|1e\d{2,})', line):
                if "ETH-017" not in file_findings:
                    _add("ETH-017", "Precision Loss in Division", "MEDIUM", 0.70,
                         sol_file, i, stripped,
                         "Division by very large denominator (1eN). Small numerators will round to zero.",
                         "Use higher precision intermediates or mulDiv for precise division.",
                         "arithmetic")
                    file_findings.add("ETH-017")
            elif re.search(r'\b\w+\s*/\s*\w+\s*;', line) and "10" not in line:
                if any(kw in cl for kw in ["price", "rate", "ratio", "share", "reward", "precision", "debt"]):
                    if "ETH-017" not in file_findings:
                        _add("ETH-017", "Precision Loss in Division", "MEDIUM", 0.55,
                             sol_file, i, stripped,
                             "Integer division truncates result. May cause precision loss in financial calculations.",
                             "Use higher precision intermediates or mulDiv for precise division.",
                             "arithmetic")
                        file_findings.add("ETH-017")

            # ─── ETH-018: Unchecked External Call Return ───────────
            if ".call(" in line or ".call{" in line:
                has_check = False
                for j in range(i, min(i + 4, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if "require" in ctx or "if" in ctx or "success" in ctx or "assert" in ctx:
                        has_check = True
                        break
                if not has_check:
                    _add("ETH-018", "Unchecked External Call Return", "HIGH", 0.70,
                         sol_file, i, stripped,
                         "Low-level call return value not checked.",
                         "Check return value: (bool success, ) = addr.call(...); require(success);",
                         "external-calls", "SWC-104")

            # ─── ETH-019: delegatecall ─────────────────────────────
            if "delegatecall(" in line:
                _add("ETH-019", "Delegatecall Usage", "CRITICAL", 0.75,
                     sol_file, i, stripped,
                     "delegatecall executes code in caller's context. Untrusted targets can overwrite storage.",
                     "Only delegatecall to trusted, immutable contracts. Verify storage layout.",
                     "external-calls", "SWC-112")

            # ─── ETH-021: DoS with Failed Call ─────────────────────
            # Pattern 1: .transfer/.send in loop
            if (".transfer(" in line or ".send(" in line) and "for" in cl[max(0, content.find(line)-200):content.find(line)]:
                _add("ETH-021", "DoS with Failed Call in Loop", "HIGH", 0.70,
                     sol_file, i, stripped,
                     ".transfer()/.send() in loop context. Single failure reverts entire batch.",
                     "Use pull-payment pattern. Let recipients withdraw instead of pushing funds.",
                     "gas-dos", "SWC-113")
            # Pattern 2: call{value:} + require(sent) — external call can permanently block function
            if ".call{value:" in line or ".call{ value:" in line:
                for j in range(i, min(i + 3, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if re.search(r'require\s*\(\s*\w+\s*,', ctx):
                        if "ETH-021" not in file_findings:
                            _add("ETH-021", "DoS via Required External Call", "HIGH", 0.65,
                                 sol_file, i, stripped,
                                 "External call with required success. If callee reverts, function is permanently blocked.",
                                 "Use pull-payment pattern or continue on failure. Don't require external call success.",
                                 "gas-dos", "SWC-113")
                            file_findings.add("ETH-021")
                        break

            # ─── ETH-024: Oracle Manipulation ──────────────────────
            if "balanceOf(address(this))" in line and any(k in cl for k in ["price", "getprice", "rate", "oracle", "getreserve"]):
                _add("ETH-024", "Price Calculation via balanceOf", "CRITICAL", 0.75,
                     sol_file, i, stripped,
                     "Using balanceOf(address(this)) for price calculation. Manipulable via flash loans or donations.",
                     "Use manipulation-resistant oracle (Chainlink, TWAP). Never use spot balance for pricing.",
                     "oracle")
            # ETH-024: getReserves() used for price/rate calculation
            if "getReserves()" in line and any(k in cl for k in ["rate", "price", "borrow", "liquidat", "collateral", "value"]):
                _add("ETH-024", "Oracle Manipulation via Spot Reserves", "CRITICAL", 0.80,
                     sol_file, i, stripped,
                     "Using Uniswap getReserves() spot price for financial calculations. Trivially manipulable via flash swap.",
                     "Use Uniswap V3 TWAP oracle or Chainlink price feed instead of spot reserves.",
                     "oracle")

            # ─── ETH-025: Flash Loan Pattern ──────────────────────
            if re.search(r'function\s+flashLoan|flashMint|flashBorrow', line, re.IGNORECASE):
                _add("ETH-025", "Flash Loan Function", "HIGH", 0.65,
                     sol_file, i, stripped,
                     "Flash loan function detected. Verify all dependent state is flash-loan resistant.",
                     "Add same-block protection. Ensure oracle prices are not manipulable within a single tx.",
                     "oracle")

            # ─── ETH-027: Missing Slippage Protection ──────────────
            if "amountOutMin" in line and re.search(r'amountOutMin\s*[=:]\s*0\b', line):
                _add("ETH-027", "Zero Slippage Protection", "HIGH", 0.85,
                     sol_file, i, stripped,
                     "amountOutMin set to 0 — accepts any output amount including total loss.",
                     "Allow user to specify minimum output. Never hardcode amountOutMin to 0.",
                     "defi")
            # ETH-027: swapExactTokensForTokens/swapExactETHForTokens with 0 as second argument (single line)
            if re.search(r'swap\w*\(\s*[^,]+,\s*0\s*,', line, re.IGNORECASE) and "ETH-027" not in file_findings:
                _add("ETH-027", "Zero Slippage in Swap Call", "HIGH", 0.85,
                     sol_file, i, stripped,
                     "Swap call with 0 as minimum output amount. Accepts any slippage including total loss.",
                     "Allow user to specify minimum output. Never hardcode min output to 0.",
                     "defi")
                file_findings.add("ETH-027")
            # ETH-027: multi-line swap call — function name on one line, 0 as amountOutMin on next lines
            if re.search(r'swap\w*\w*Tokens\w*\(', line, re.IGNORECASE) and "ETH-027" not in file_findings:
                # Join next 5 lines to check second argument
                window = "".join(lines[i - 1:min(i + 5, len(lines))])
                if re.search(r'swap\w*\([^,]+,\s*0\s*,', window, re.DOTALL | re.IGNORECASE):
                    _add("ETH-027", "Zero Slippage in Swap Call", "HIGH", 0.85,
                         sol_file, i, stripped,
                         "Swap call with 0 as minimum output amount. Accepts any slippage including total loss.",
                         "Allow user to specify minimum output. Never hardcode min output to 0.",
                         "defi")
                    file_findings.add("ETH-027")

            # ─── ETH-028: Stale Oracle Data ────────────────────────
            if "latestRoundData" in line:
                # Check if THIS call destructures without staleness fields
                # Pattern: (, int256 answer, , , ) = ...latestRoundData() — discards updatedAt/answeredInRound
                discards_fields = bool(re.search(r'\(\s*,.*,\s*,\s*\)', line) or
                                       re.search(r',\s*int256\s+\w+\s*,\s*,\s*,\s*\)', line))
                # Also check within nearby lines (same function scope) for staleness checks
                has_staleness_in_scope = False
                for j in range(i, min(i + 12, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    # Stop at next function boundary
                    if j > i and re.search(r'^\s*function\s', ctx):
                        break
                    if "updatedAt" in ctx or "answeredInRound" in ctx or "stale" in ctx.lower():
                        has_staleness_in_scope = True
                        break
                if discards_fields or not has_staleness_in_scope:
                    if "ETH-028" not in file_findings:
                        _add("ETH-028", "Stale Oracle Data", "HIGH", 0.80,
                             sol_file, i, stripped,
                             "latestRoundData() called without staleness checks (updatedAt/answeredInRound).",
                             "Check: require(answeredInRound >= roundId); require(updatedAt > 0); require(answer > 0);",
                             "oracle")
                        file_findings.add("ETH-028")

            # ─── ETH-029: Uninitialized Storage / Data Location ────
            if re.search(r'\bstorage\b', line) and "function" not in line and "pragma" not in line:
                if "=" not in line:
                    _add("ETH-029", "Uninitialized Storage Pointer", "HIGH", 0.65,
                         sol_file, i, stripped,
                         "Storage pointer declared without initialization. May point to unexpected slot.",
                         "Initialize storage pointers explicitly. Use memory for local variables.",
                         "storage", "SWC-109")

            # ─── ETH-030: Storage Collision (Proxy) ────────────────
            if "delegatecall" in line and "implementation" in cl:
                if "ETH-030" not in file_findings:
                    _add("ETH-030", "Storage Collision Risk (Proxy)", "CRITICAL", 0.70,
                         sol_file, i, stripped,
                         "delegatecall in proxy pattern. Storage layout mismatch causes slot collision.",
                         "Use EIP-1967 storage slots. Ensure proxy and impl have compatible storage layouts.",
                         "storage", "SWC-124")
                    file_findings.add("ETH-030")
            # ETH-030 variant: state variable in proxy contract (collision with impl slot 0)
            if re.search(r'contract\s+\w+\s+is\s+\w*(?:Proxy|Upgradeable)', line):
                # Look for private/internal state vars in next 10 lines
                for j in range(i + 1, min(i + 15, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if re.search(r'^\s+(?:address|uint256|bytes32|bool)\s+(?:private|internal)\s+\w+', ctx):
                        # Strip comments before checking for SLOT keyword
                        code_part = ctx.split("//")[0]
                        if "constant" not in code_part and "immutable" not in code_part and \
                           "_SLOT" not in code_part.upper():
                            if "ETH-030" not in file_findings:
                                _add("ETH-030", "Storage Collision — State Var in Proxy", "CRITICAL", 0.80,
                                     sol_file, j, ctx.strip(),
                                     "State variable in proxy contract collides with implementation slot 0.",
                                     "Remove state variables from proxy. Use EIP-1967 storage slots.",
                                     "storage", "SWC-124")
                                file_findings.add("ETH-030")
                            break
                    if re.search(r'^\s*(function|constructor|event)', ctx):
                        break
            # ETH-030 variant: non-constant _IMPLEMENTATION_SLOT
            if re.search(r'bytes32\s+(?:internal|private)\s+\w*(?:SLOT|slot)\w*\s*=\s*keccak256', line):
                if "constant" not in line:
                    if "ETH-030" not in file_findings:
                        _add("ETH-030", "Mutable Storage Slot (Must Be Constant)", "CRITICAL", 0.85,
                             sol_file, i, stripped,
                             "Storage slot variable is not constant. Can be overwritten, breaking proxy.",
                             "Mark storage slot as constant: bytes32 constant internal _IMPL_SLOT = keccak256(...);",
                             "storage", "SWC-124")
                        file_findings.add("ETH-030")

            # ─── ETH-037: Weak Randomness ──────────────────────────
            if ("block.timestamp" in line or "block.prevrandao" in line or "blockhash(" in line) and \
               ("random" in cl or "seed" in cl or "lottery" in cl or "guess" in cl or "winner" in cl):
                _add("ETH-037", "Weak Randomness from Chain Attributes", "HIGH", 0.75,
                     sol_file, i, stripped,
                     "Block attributes are miner-manipulable. Not suitable for randomness.",
                     "Use Chainlink VRF or commit-reveal scheme.",
                     "logic", "SWC-120")
            # ETH-037: pure function named "random" returning a constant (trivially predictable)
            if re.search(r'function\s+\w*[Rr]andom\w*\(', line) and "pure" in line:
                _add("ETH-037", "Predictable 'Random' Function (pure)", "HIGH", 0.90,
                     sol_file, i, stripped,
                     "Function named 'random' is declared pure — cannot access any entropy source. Return value is deterministic.",
                     "Use Chainlink VRF or commit-reveal scheme for randomness.",
                     "logic", "SWC-120")

            # ─── ETH-038: ecrecover Without Zero-Check ─────────────
            if "ecrecover" in line:
                has_zero_check = False
                for j in range(i, min(i + 8, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if "address(0)" in ctx or "!= 0" in ctx or "!= address" in ctx:
                        has_zero_check = True
                        break
                if not has_zero_check:
                    _add("ETH-038", "ecrecover Returns address(0)", "HIGH", 0.80,
                         sol_file, i, stripped,
                         "ecrecover may return address(0) for invalid signatures. Not checked.",
                         "Verify: require(recoveredAddress != address(0)). Use OpenZeppelin ECDSA.",
                         "logic", "SWC-117")

            # ─── ETH-039: Signature Replay ─────────────────────────
            if "ecrecover" in line and not has_chainid:
                if "ETH-039" not in file_findings:
                    _add("ETH-039", "Signature Replay Risk", "CRITICAL", 0.70,
                         sol_file, i, stripped,
                         "ecrecover used without chain ID protection. Signature can be replayed cross-chain.",
                         "Include block.chainid and contract address in signed hash. Use EIP-712.",
                         "logic", "SWC-121")
                    file_findings.add("ETH-039")

            # ─── ETH-041: ERC-20 Non-standard Returns ──────────────
            # Detect token.transfer() / token.transferFrom() without SafeERC20 wrapper
            # Even if SafeERC20 is imported, the VULNERABLE line uses direct .transfer()
            if re.search(r'\b\w+\.\s*transfer\s*\(', line) and "safeTransfer" not in line:
                # Exclude ETH transfers (payable, msg.sender, address.transfer)
                if not re.search(r'payable\s*\(', line) and ".call{" not in line and \
                   "msg.sender.transfer" not in line and "address" not in line.split(".transfer")[0].split()[-1:]:
                    # Check if this looks like a token transfer (has 2 args: addr, amount)
                    if re.search(r'\.transfer\s*\(\s*\w+.*,\s*\w+', line):
                        _add("ETH-041", "ERC-20 Transfer Without SafeERC20", "HIGH", 0.75,
                             sol_file, i, stripped,
                             "ERC-20 transfer without SafeERC20. Some tokens (USDT) don't return bool.",
                             "Use OpenZeppelin SafeERC20: token.safeTransfer() instead of token.transfer().",
                             "token")

            # ─── ETH-042: Fee-on-Transfer Token ────────────────────
            if "transferFrom" in line and not has_safe_erc20_usage:
                has_balance_check = False
                for j in range(max(1, i - 3), min(i + 5, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if "balanceOf" in ctx and ("before" in ctx.lower() or "after" in ctx.lower() or "bal" in ctx.lower()):
                        has_balance_check = True
                        break
                if not has_balance_check and "ETH-042" not in file_findings:
                    _add("ETH-042", "Fee-on-Transfer Token Incompatibility", "HIGH", 0.55,
                         sol_file, i, stripped,
                         "transferFrom without balance diff check. Fee-on-transfer tokens deliver less than expected.",
                         "Check balanceOf before/after transferFrom to account for transfer fees.",
                         "token")
                    file_findings.add("ETH-042")

            # ─── ETH-044: ERC-777 Reentrancy Hook ──────────────────
            if re.search(r'ERC777|IERC777|tokensReceived|tokensToSend', line):
                if not has_reentrancy_guard:
                    _add("ETH-044", "ERC-777 Reentrancy via Token Hook", "HIGH", 0.75,
                         sol_file, i, stripped,
                         "ERC-777 token hooks can trigger reentrancy. No ReentrancyGuard detected.",
                         "Add nonReentrant modifier or use ERC-20 instead of ERC-777.",
                         "token")

            # ─── ETH-046: Approval Race Condition ──────────────────
            if ".approve(" in line and "safeApprove" not in line:
                if "ETH-046" not in file_findings:
                    _add("ETH-046", "ERC-20 Approve Race Condition", "MEDIUM", 0.60,
                         sol_file, i, stripped,
                         "approve() is vulnerable to front-running race condition.",
                         "Use safeIncreaseAllowance/safeDecreaseAllowance or set to 0 first.",
                         "token")
                    file_findings.add("ETH-046")

            # ─── ETH-048: Token Supply Manipulation ────────────────
            if "_mint(" in line:
                has_auth = False
                # Check within 3 lines above for modifier/require
                for j in range(max(1, i - 3), i + 1):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if any(m in ctx for m in ["onlyOwner", "onlyRole", "only", "auth", "require"]):
                        has_auth = True
                        break
                if not has_auth:
                    _add("ETH-048", "Unprotected Token Minting", "HIGH", 0.65,
                         sol_file, i, stripped,
                         "_mint() called without access control. May allow unauthorized token creation.",
                         "Restrict minting to authorized roles with onlyOwner/onlyRole modifier.",
                         "token")
            # ETH-048 variant: onSwap / reserve manipulation (AMM/pool swap amount dependent on manipulable reserves)
            if re.search(r'function\s+onSwap\b', line) or \
               (re.search(r'reserves?\w*\s*(?:TokenIn|TokenOut|In|Out)', line, re.IGNORECASE) and
                any(k in cl for k in ["swap", "onswap", "pool", "amm"])):
                if "ETH-048" not in file_findings:
                    _add("ETH-048", "Swap Amount Dependent on Manipulable Reserves", "HIGH", 0.65,
                         sol_file, i, stripped,
                         "Swap callback uses reserve parameters that can be manipulated via flash loans.",
                         "Use TWAP oracle or verify reserves haven't been manipulated in same block.",
                         "token")
                    file_findings.add("ETH-048")

            # ─── ETH-057: Vault Share Inflation ────────────────────
            if re.search(r'totalSupply\s*(\(\s*\))?\s*==\s*0|totalShares\s*==\s*0', line):
                if any(k in cl for k in ["deposit", "mint", "share"]):
                    _add("ETH-057", "Vault Share Inflation / First Depositor Attack", "CRITICAL", 0.75,
                         sol_file, i, stripped,
                         "Share calculation when totalSupply==0 is vulnerable to first-depositor inflation attack.",
                         "Add virtual shares/assets offset (ERC4626) or mint minimum dead shares on first deposit.",
                         "defi")
            # ETH-057: balanceOf-based share calculation (shares = amount * totalSupply / bal pattern)
            if re.search(r'totalSupply\s*[/\*].*balanceOf|balanceOf.*[/\*].*totalSupply', line):
                if any(k in cl for k in ["deposit", "withdraw", "share", "vault"]):
                    if "ETH-057" not in file_findings:
                        _add("ETH-057", "Balance-Based Share Calculation (Donation Attack Risk)", "HIGH", 0.70,
                             sol_file, i, stripped,
                             "Share price derived from balanceOf/totalSupply ratio. Vulnerable to donation attacks.",
                             "Use internal accounting instead of balanceOf. Add virtual offset or minimum deposit.",
                             "defi")
                        file_findings.add("ETH-057")

            # ─── ETH-060: Missing Deadline ────────────────────────
            if "type(uint256).max" in line and any(k in cl for k in ["deadline", "swap", "router"]):
                _add("ETH-060", "Hardcoded Max Deadline", "MEDIUM", 0.70,
                     sol_file, i, stripped,
                     "Deadline set to type(uint256).max — effectively no deadline protection.",
                     "Allow user to specify deadline: require(block.timestamp <= deadline).",
                     "defi")
            # ETH-060: deadline: block.timestamp (no actual deadline protection)
            if re.search(r'deadline\s*:\s*block\.timestamp\b', line):
                _add("ETH-060", "Ineffective Deadline (block.timestamp)", "MEDIUM", 0.80,
                     sol_file, i, stripped,
                     "Deadline set to block.timestamp — always passes. No protection against tx delay.",
                     "Use block.timestamp + buffer or allow user to specify deadline.",
                     "defi")
            # ETH-060: amountOutMinimum: 0 (no slippage protection in swap struct)
            if re.search(r'amountOut(?:Minimum|Min)\s*:\s*0\b', line):
                _add("ETH-060", "Zero Slippage in Swap Parameters", "HIGH", 0.85,
                     sol_file, i, stripped,
                     "amountOutMinimum set to 0 in swap params — accepts any output amount.",
                     "Allow user to specify minimum output. Never hardcode to 0.",
                     "defi")

            # ─── ETH-064: Unprotected Callback ─────────────────────
            if re.search(r'function\s+(onERC721Received|onERC1155Received|onFlashLoan|uniswapV\dCall)', line):
                has_sender_check = False
                for j in range(i, min(i + 8, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if "msg.sender" in ctx and ("require" in ctx or "==" in ctx or "if" in ctx):
                        has_sender_check = True
                        break
                if not has_sender_check:
                    _add("ETH-064", "Unprotected Callback Handler", "HIGH", 0.65,
                         sol_file, i, stripped,
                         "Callback function without msg.sender validation. May allow unauthorized invocation.",
                         "Verify msg.sender is the expected caller in callback functions.",
                         "defi")

            # ─── ETH-066: Unbounded loop ───────────────────────────
            if "for" in line and ".length" in line:
                _add("ETH-066", "Unbounded Loop / Array Growth", "HIGH", 0.70,
                     sol_file, i, stripped,
                     "Loop iterates over dynamic array length. May exceed block gas limit.",
                     "Add loop bounds or use pagination pattern.",
                     "gas-dos", "SWC-128")

            # ─── ETH-071: Floating pragma ──────────────────────────
            if "pragma solidity ^" in line or "pragma solidity >=" in line:
                _add("ETH-071", "Floating Pragma", "LOW", 0.95,
                     sol_file, i, stripped,
                     "Floating pragma allows compilation with different compiler versions.",
                     "Lock pragma to specific version: pragma solidity 0.8.x;",
                     "miscellaneous", "SWC-103")

            # ─── ETH-072: Outdated compiler ────────────────────────
            if "pragma solidity" in line:
                for old_ver in ["0.4.", "0.5.", "0.6.", "0.7."]:
                    if f"pragma solidity {old_ver}" in line or f"pragma solidity ^{old_ver}" in line:
                        _add("ETH-072", "Outdated Compiler Version", "LOW", 0.95,
                             sol_file, i, stripped,
                             "Using outdated Solidity version. Missing overflow protection and security fixes.",
                             "Upgrade to Solidity 0.8.x+ for built-in overflow checks.",
                             "miscellaneous", "SWC-102")
                        break

            # ─── ETH-073: abi.encodePacked ─────────────────────────
            if "abi.encodePacked" in line:
                _add("ETH-073", "Hash Collision with abi.encodePacked", "MEDIUM", 0.65,
                     sol_file, i, stripped,
                     "abi.encodePacked with multiple dynamic types can cause hash collisions.",
                     "Use abi.encode instead of abi.encodePacked when hashing multiple dynamic types.",
                     "logic", "SWC-133")

            # ─── ETH-075: Code With No Effects ─────────────────────
            if re.search(r'\bdelete\s+\w+\[', line) and "mapping" not in line:
                _add("ETH-075", "Incorrect Array Deletion", "MEDIUM", 0.65,
                     sol_file, i, stripped,
                     "delete on array element sets to zero but doesn't remove. Leaves gap in array.",
                     "Swap with last element and pop, or shift elements left.",
                     "miscellaneous", "SWC-135")

            if re.search(r'\bdelete\s+\w+\s*;', line):
                # Check if it's a struct (look for mapping in struct context)
                if "struct" in cl and "mapping" in cl:
                    _add("ETH-075", "Incomplete Struct Deletion", "MEDIUM", 0.60,
                         sol_file, i, stripped,
                         "delete on struct with nested mapping doesn't clear the mapping.",
                         "Manually clear mapping entries before deleting struct.",
                         "miscellaneous", "SWC-135")

            # ETH-075 variant: validation loop bypassable with empty array
            # Pattern: for (... i < arr.length ...) { verify/require } then action OUTSIDE loop
            if re.search(r'for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.length', line):
                # Check if loop validates but action is after loop
                has_validation_in_loop = False
                loop_end = -1
                brace_depth = 0
                for j in range(i, min(i + 20, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    brace_depth += ctx.count("{") - ctx.count("}")
                    if "verify" in ctx.lower() or "require" in ctx or "ecrecover" in ctx:
                        has_validation_in_loop = True
                    if brace_depth <= 0 and j > i:
                        loop_end = j
                        break
                if has_validation_in_loop and loop_end > 0:
                    # Check lines after loop for transfer/send/action
                    for j in range(loop_end, min(loop_end + 5, len(lines) + 1)):
                        ctx = lines[j - 1] if j <= len(lines) else ""
                        if ".transfer(" in ctx or ".call{" in ctx or ".send(" in ctx:
                            _add("ETH-075", "Empty Array Bypasses Validation Loop", "HIGH", 0.75,
                                 sol_file, i, stripped,
                                 "Validation in loop can be bypassed by passing empty array. Action executes regardless.",
                                 "Add require(array.length > 0) before loop to prevent empty input bypass.",
                                 "miscellaneous", "SWC-135")
                            break

            # ETH-075 variant: return in nested for loop (should be break)
            if "return;" in line or "return ;" in line:
                # Check if we're inside nested loops (2+ for loops above)
                for_count = 0
                for j in range(max(1, i - 15), i):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if "for" in ctx and "(" in ctx:
                        for_count += 1
                if for_count >= 2:
                    _add("ETH-075", "Return in Nested Loop (Should Be Break)", "MEDIUM", 0.70,
                         sol_file, i, stripped,
                         "return inside nested loop exits entire function. Use break to exit inner loop only.",
                         "Replace return with break in inner loop to continue outer loop processing.",
                         "miscellaneous", "SWC-135")

            # ─── ETH-078: Private Data On-Chain ────────────────────
            if re.search(r'\bprivate\b', line) and any(kw in line.lower() for kw in [
                    "password", "secret", "key", "pin", "seed", "private"]):
                _add("ETH-078", "Sensitive Private Data On-Chain", "MEDIUM", 0.70,
                     sol_file, i, stripped,
                     "Private variables are still readable on-chain via storage slots.",
                     "Never store secrets on-chain. Use commit-reveal or off-chain storage.",
                     "miscellaneous", "SWC-136")

            # ETH-078 variant: any private state variable
            if re.search(r'^\s+(uint|int|address|bytes|string|bool)\s+private\s+\w+', line):
                if "ETH-078" not in file_findings and "private" in cl:
                    _add("ETH-078", "Private State Variable (Readable On-Chain)", "LOW", 0.50,
                         sol_file, i, stripped,
                         "Private variables are readable via storage slot inspection despite visibility.",
                         "Do not rely on 'private' for data confidentiality. All on-chain data is public.",
                         "miscellaneous", "SWC-136")
                    file_findings.add("ETH-078")

            # ETH-078 variant: exposed/predictable metadata (NFT IPFS URI)
            if re.search(r'ipfs|dweb|metadata|tokenURI|baseURI', line, re.IGNORECASE):
                if any(k in cl for k in ["nft", "erc721", "mint", "tokenid"]):
                    if "ETH-078" not in file_findings:
                        _add("ETH-078", "Exposed NFT Metadata / Predictable URI", "MEDIUM", 0.60,
                             sol_file, i, stripped,
                             "NFT metadata URI is predictable/exposed before mint. Attacker can snipe rare NFTs.",
                             "Use commit-reveal pattern or encrypt metadata until minting completes.",
                             "miscellaneous", "SWC-136")
                        file_findings.add("ETH-078")

            # ─── ETH-079: Hardcoded gas (.transfer / .send) ───────
            if ".transfer(" in line or ".send(" in line:
                _add("ETH-079", "Hardcoded Gas Amount (transfer/send)", "LOW", 0.80,
                     sol_file, i, stripped,
                     ".transfer() and .send() forward only 2300 gas.",
                     "Use .call{value: amount}('') with reentrancy guard instead.",
                     "miscellaneous", "SWC-134")

            # ─── ETH-081: Transient storage slot collision ─────────
            if "tstore(" in line:
                slot_m = re.search(r'tstore\s*\(\s*(0x[0-9a-fA-F]{1,4}|[0-9]{1,3})\s*,', line)
                if slot_m:
                    _add("ETH-081", "Transient Storage Slot Collision Risk", "CRITICAL", 0.80,
                         sol_file, i, stripped,
                         f"TSTORE uses hardcoded small slot ({slot_m.group(1)}). Risk of collision.",
                         "Use namespaced slots: bytes32 slot = keccak256('Contract.lock');",
                         "transient-storage")

            # ─── ETH-086: tx.origin == msg.sender (EIP-7702) ──────
            if "tx.origin" in line and "msg.sender" in line and ("==" in line or "require" in line):
                _add("ETH-086", "Broken tx.origin == msg.sender (EIP-7702)", "CRITICAL", 0.90,
                     sol_file, i, stripped,
                     "tx.origin == msg.sender no longer guarantees EOA after EIP-7702.",
                     "Remove tx.origin == msg.sender check.",
                     "access-control")

            # ─── ETH-089: extcodesize/isContract ──────────────────
            if "extcodesize" in line or "isContract" in line:
                _add("ETH-089", "EOA Code Assumption Failure (EIP-7702)", "HIGH", 0.70,
                     sol_file, i, stripped,
                     "extcodesize/isContract cannot reliably distinguish EOAs from contracts.",
                     "Do not rely on code size to determine account type.",
                     "access-control")

            # ─── ETH-097: Known Compiler Bug (Dirty Bytes) ─────────
            if is_dirty_bytes_ver and ".push(" in line and "bytes" in cl:
                _add("ETH-097", "Known Compiler Bug — Dirty Bytes", "HIGH", 0.70,
                     sol_file, i, stripped,
                     f"Solidity {pragma_ver} affected by dirty bytes bug (fixed in 0.8.15). bytes.push() may include dirty data.",
                     "Upgrade to Solidity >= 0.8.15 to fix dirty bytes issue.",
                     "miscellaneous")

            # ─── ETH-098: Missing input validation ─────────────────
            if "function" in line and ("external" in line or "public" in line):
                params_m = re.search(r'function\s+\w+\s*\(([^)]+)\)', line)
                if params_m:
                    params = params_m.group(1)
                    has_uint = "uint" in params or "int" in params
                    has_addr = "address" in params
                    if has_uint or has_addr:
                        has_validation = False
                        for j in range(i, min(i + 6, len(lines) + 1)):
                            ctx = lines[j - 1] if j <= len(lines) else ""
                            if "require(" in ctx or "revert" in ctx or "if (" in ctx:
                                has_validation = True
                                break
                        if not has_validation:
                            _add("ETH-098", "Missing Input Validation", "HIGH", 0.60,
                                 sol_file, i, stripped,
                                 "External/public function accepts parameters without input validation.",
                                 "Add require() checks for parameter bounds and zero address.",
                                 "input-validation")

            # ETH-098 variant: msg.value check inside for loop (Immunefi pattern)
            # Each iteration checks same msg.value — allows multiple ops for single payment
            if re.search(r'require\s*\(\s*msg\.value\s*>=', line):
                # Check if we're inside a for loop
                for j in range(max(1, i - 10), i):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if re.search(r'for\s*\(', ctx):
                        _add("ETH-098", "Invariant msg.value Check in Loop", "HIGH", 0.80,
                             sol_file, i, stripped,
                             "msg.value checked in loop — same value passes every iteration. Allows multiple operations for single payment.",
                             "Check total cost outside loop: require(msg.value >= price * amount).",
                             "input-validation")
                        break

            # ─── ETH-032: Unexpected Ether Balance ─────────────────
            # address(this).balance in equality check (can be manipulated via selfdestruct)
            if "address(this).balance" in line:
                if re.search(r'==\s*\d|==\s*\w+', line) or re.search(r'require\s*\(.*address\(this\)\.balance\s*==', line):
                    _add("ETH-032", "Strict Equality on Ether Balance", "HIGH", 0.80,
                         sol_file, i, stripped,
                         "Strict equality check on address(this).balance. Attacker can force ETH via selfdestruct to break invariants.",
                         "Use >= or <= instead of == for balance checks. Never assume exact balance.",
                         "logic", "SWC-132")

            # ─── ETH-033: Write to Arbitrary Storage ──────────────
            # Array length manipulation (Solidity < 0.6.0)
            if is_old_pragma and re.search(r'\.\s*length\s*[-+]?=', line):
                _add("ETH-033", "Array Length Manipulation (Arbitrary Storage Write)", "CRITICAL", 0.90,
                     sol_file, i, stripped,
                     "Direct array .length modification in Solidity < 0.6.0 enables arbitrary storage slot writes via array underflow.",
                     "Upgrade to Solidity >= 0.6.0 where direct .length modification is prohibited.",
                     "storage", "SWC-124")
            # Assembly sstore with user-influenced slot
            if "sstore" in line and "assembly" in cl:
                _add("ETH-033", "Assembly sstore (Potential Arbitrary Storage Write)", "HIGH", 0.70,
                     sol_file, i, stripped,
                     "Direct storage write via sstore in assembly. If slot is user-controllable, enables arbitrary storage overwrites.",
                     "Validate storage slot values. Use Solidity state variables instead of raw sstore.",
                     "storage", "SWC-124")

            # ─── ETH-034: Strict Equality on Balance ──────────────
            if re.search(r'(balance|totalSupply|supply)\w*\s*==\s*\d', line) or \
               re.search(r'require\s*\(.*balance\w*\s*==', line, re.IGNORECASE) or \
               re.search(r'\.balanceOf\s*\([^)]*\)\s*==\s*\d', line) or \
               re.search(r'\.balance\s*==\s*\d', line):
                _add("ETH-034", "Strict Equality on Balance", "HIGH", 0.70,
                     sol_file, i, stripped,
                     "Strict equality check on balance/supply. Attacker can manipulate via transfer/selfdestruct to break invariant.",
                     "Use >= or <= instead of == for balance comparisons.",
                     "logic", "SWC-132")

            # ─── ETH-010: Uninitialized Proxy / Public init() ────
            if re.search(r'function\s+(init|initialize)\s*\(', line) and \
               ("public" in line or "external" in line):
                has_init_modifier = "initializer" in line
                if not has_init_modifier:
                    for j in range(i, min(i + 3, len(lines) + 1)):
                        ctx = lines[j - 1] if j <= len(lines) else ""
                        if "initializer" in ctx or "initialized" in ctx or "require(!_initialized" in ctx:
                            has_init_modifier = True
                            break
                if not has_init_modifier:
                    _add("ETH-010", "Uninitialized Proxy — Public init() Without Protection", "CRITICAL", 0.85,
                         sol_file, i, stripped,
                         "Public init/initialize function without initializer modifier. Anyone can call it to take ownership.",
                         "Add OpenZeppelin initializer modifier or require(!initialized) check.",
                         "proxy")

            # ─── ETH-049: Missing _disableInitializers ────────────
            if "Initializable" in line or ("initializer" in line and "modifier" not in line):
                if "ETH-049" not in file_findings:
                    if "function initialize" in cl and "_disableInitializers" not in cl:
                        _add("ETH-049", "Missing _disableInitializers in Constructor", "CRITICAL", 0.80,
                             sol_file, i, stripped,
                             "Initializable contract without _disableInitializers() in constructor. Implementation can be initialized by attacker.",
                             "Add constructor() { _disableInitializers(); } to prevent implementation takeover.",
                             "proxy")
                        file_findings.add("ETH-049")

            # ─── ETH-045: Missing Zero Address Check ──────────────
            if re.search(r'function\s+\w*(set|update|change|transfer)\w*(Owner|Admin|Manager|Address)\w*\s*\(', line, re.IGNORECASE):
                if "address" in line and ("public" in line or "external" in line):
                    has_zero_check = False
                    for j in range(i, min(i + 5, len(lines) + 1)):
                        ctx = lines[j - 1] if j <= len(lines) else ""
                        if "address(0)" in ctx and ("!=" in ctx or "require" in ctx):
                            has_zero_check = True
                            break
                    if not has_zero_check:
                        _add("ETH-045", "Missing Zero Address Check", "MEDIUM", 0.65,
                             sol_file, i, stripped,
                             "Setter function for critical address parameter without address(0) validation.",
                             "Add require(newAddr != address(0)) before assignment.",
                             "token")

            # ─── ETH-047: Infinite Approval ───────────────────────
            if "type(uint256).max" in line and "approve" in line:
                _add("ETH-047", "Infinite Token Approval", "LOW", 0.75,
                     sol_file, i, stripped,
                     "Unlimited token approval (type(uint256).max). If approved address is compromised, all tokens are at risk.",
                     "Approve only the exact amount needed. Use increaseAllowance/decreaseAllowance.",
                     "token")

            # ─── ETH-026: MEV / Sandwich Attack Risk ─────────────
            if re.search(r'\b(swap|exactInput|swapExact)\w*\(', line, re.IGNORECASE) and "ETH-026" not in file_findings:
                has_slippage = False
                has_deadline = False
                for j in range(max(1, i - 5), min(i + 10, len(lines) + 1)):
                    ctx = lines[j - 1] if j <= len(lines) else ""
                    if re.search(r'(minAmount|amountOutMin|slippage|minReturn)', ctx, re.IGNORECASE):
                        has_slippage = True
                    if re.search(r'deadline|block\.timestamp', ctx):
                        has_deadline = True
                if not has_slippage and not has_deadline:
                    _add("ETH-026", "MEV / Sandwich Attack Risk", "HIGH", 0.70,
                         sol_file, i, stripped,
                         "Swap operation without slippage protection or deadline. Vulnerable to sandwich attacks.",
                         "Add minimum output amount and transaction deadline parameters.",
                         "defi")
                    file_findings.add("ETH-026")

            # ─── ETH-076: Missing Event Emission ─────────────────
            if re.search(r'\b(owner|admin|paused|implementation)\s*=\s*', line) and \
               "function" not in line and "constructor" not in line and "event" not in line:
                if stripped and not stripped.startswith("//"):
                    has_emit = False
                    for j in range(i, min(i + 4, len(lines) + 1)):
                        ctx = lines[j - 1] if j <= len(lines) else ""
                        if "emit " in ctx:
                            has_emit = True
                            break
                    if not has_emit and "ETH-076" not in file_findings:
                        _add("ETH-076", "Missing Event Emission on Critical State Change", "LOW", 0.55,
                             sol_file, i, stripped,
                             "Critical state variable modified without event emission. Makes off-chain monitoring impossible.",
                             "Emit an event after updating critical state variables (owner, admin, implementation).",
                             "miscellaneous")
                        file_findings.add("ETH-076")

            # ─── ETH-055: Governance Manipulation ─────────────────
            if re.search(r'function\s+\w*(propose|vote|execute)\w*\s*\(', line, re.IGNORECASE):
                if "ETH-055" not in file_findings:
                    has_snapshot = False
                    for j in range(max(1, i - 20), min(i + 20, len(lines) + 1)):
                        ctx = lines[j - 1] if j <= len(lines) else ""
                        if "snapshot" in ctx.lower() or "checkpoint" in ctx.lower() or \
                           "getPastVotes" in ctx or "getPriorVotes" in ctx:
                            has_snapshot = True
                            break
                    if not has_snapshot:
                        _add("ETH-055", "Governance Without Vote Snapshot", "HIGH", 0.65,
                             sol_file, i, stripped,
                             "Governance function without vote snapshotting. Attacker can flash-loan tokens to manipulate votes.",
                             "Use ERC20Votes with getPastVotes() and proposal snapshot blocks.",
                             "defi")
                        file_findings.add("ETH-055")

            # ─── ETH-065: Cross-protocol Integration Risk ────────
            # User-supplied protocol/contract address used for calls
            if re.search(r'function\s+\w+\s*\([^)]*(?:Protocol|address)\s+\w*(?:protocol|target|router|pool)', line, re.IGNORECASE):
                if "ETH-065" not in file_findings:
                    _add("ETH-065", "User-Supplied Protocol Address (Cross-Protocol Risk)", "MEDIUM", 0.60,
                         sol_file, i, stripped,
                         "Function accepts user-controlled protocol/contract address. Attacker can pass malicious contract.",
                         "Whitelist allowed protocol addresses or validate against a registry.",
                         "defi")
                    file_findings.add("ETH-065")

    return findings


def run_full_scan(target_path: str, tools: list = None) -> list:
    """Run all available tools and merge findings with false positive reduction.

    Combines scan_patterns(), run_slither(), and run_aderyn() outputs,
    then applies cross-tool confidence boosting and context-based FP filtering.

    Args:
        target_path: Path to contracts directory or project root
        tools: List of tools to run. Default: ["patterns", "slither", "aderyn"]

    Returns:
        Deduplicated, filtered list of Finding objects
    """
    from finding_merger import (
        merge_findings, filter_low_confidence, apply_context_filters,
        normalize_slither_findings,
    )

    if tools is None:
        tools = ["patterns", "slither", "aderyn"]

    findings_lists = []

    # Always run pattern scanner
    if "patterns" in tools:
        pattern_findings = scan_patterns(target_path)
        findings_lists.append(pattern_findings)

    # Run Slither if requested
    if "slither" in tools:
        slither_findings = run_slither(target_path)
        slither_findings = normalize_slither_findings(slither_findings)
        findings_lists.append(slither_findings)

    # Run Aderyn if requested
    if "aderyn" in tools:
        aderyn_findings = run_aderyn(target_path)
        findings_lists.append(aderyn_findings)

    # Merge and deduplicate across tools
    merged = merge_findings(findings_lists)

    # Apply context-based false positive filtering
    # Read all .sol files to build full content for context analysis
    sol_files = list(Path(target_path).rglob("*.sol"))
    full_content = ""
    for sol_file in sol_files:
        try:
            full_content += sol_file.read_text() + "\n"
        except Exception:
            continue

    if full_content:
        merged = apply_context_filters(merged, full_content)

    # Filter low-confidence findings
    merged = filter_low_confidence(merged, threshold=0.7)

    return merged


def main():
    parser = argparse.ArgumentParser(description="SolidityGuard - Smart Contract Security Scanner")
    parser.add_argument("target", help="Path to contracts directory or project root")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("-f", "--file", help="Output file path")
    parser.add_argument("--tools", default="slither,aderyn,patterns",
                        help="Comma-separated list of tools to run")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist")
        sys.exit(1)

    tools = args.tools.split(",")
    results = ScanResults(
        project=os.path.basename(os.path.abspath(args.target)),
        timestamp=datetime.now().isoformat(),
        tools_used=tools,
    )

    print(f"SolidityGuard v1.0.0 — Scanning {args.target}")
    print(f"Tools: {', '.join(tools)}")
    print("=" * 60)

    if "slither" in tools:
        print("\n[1/3] Running Slither...")
        slither_findings = run_slither(args.target)
        for f in slither_findings:
            results.add_finding(f)
        print(f"  Found {len(slither_findings)} issues")

    if "aderyn" in tools:
        print("\n[2/3] Running Aderyn...")
        aderyn_findings = run_aderyn(args.target)
        for f in aderyn_findings:
            results.add_finding(f)
        print(f"  Found {len(aderyn_findings)} issues")

    if "patterns" in tools:
        print("\n[3/3] Running pattern scanner...")
        pattern_findings = scan_patterns(args.target)
        for f in pattern_findings:
            results.add_finding(f)
        print(f"  Found {len(pattern_findings)} issues")

    results.calculate_score()

    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print(f"  Critical: {results.summary['critical']}")
    print(f"  High:     {results.summary['high']}")
    print(f"  Medium:   {results.summary['medium']}")
    print(f"  Low:      {results.summary['low']}")
    print(f"  Info:     {results.summary['informational']}")
    print(f"  Total:    {results.summary['total']}")
    print(f"  Security Score: {results.security_score}/100")
    print("=" * 60)

    if args.output == "json":
        output = json.dumps(results.to_dict(), indent=2)
        if args.file:
            with open(args.file, "w") as f:
                f.write(output)
            print(f"\nResults written to {args.file}")
        else:
            print(output)
    elif args.file:
        with open(args.file, "w") as f:
            json.dump(results.to_dict(), f, indent=2)
        print(f"\nResults written to {args.file}")


if __name__ == "__main__":
    main()
