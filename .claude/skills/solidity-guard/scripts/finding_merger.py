#!/usr/bin/env python3
"""
SolidityGuard Finding Merger & False Positive Reducer

Merges findings from multiple tools (Slither, Aderyn, pattern-scanner),
boosts confidence on multi-tool agreement, and filters false positives
based on code context.

Usage:
    from finding_merger import merge_findings, filter_low_confidence, apply_context_filters
"""

import re


# ── Slither detector name → ETH pattern ID mapping ──────────────────────────
SLITHER_TO_ETH = {
    # Reentrancy
    "reentrancy-eth": "ETH-001",
    "reentrancy-no-eth": "ETH-001",
    "reentrancy-benign": "ETH-001",
    "reentrancy-events": "ETH-001",
    "reentrancy-unlimited-gas": "ETH-001",
    # Access Control
    "tx-origin": "ETH-007",
    "suicidal": "ETH-008",
    "unprotected-upgrade": "ETH-052",
    # Arithmetic
    "divide-before-multiply": "ETH-014",
    # External Calls
    "unchecked-lowlevel": "ETH-018",
    "unchecked-send": "ETH-018",
    "low-level-calls": "ETH-020",
    "controlled-delegatecall": "ETH-019",
    "delegatecall-loop": "ETH-019",
    "arbitrary-send-eth": "ETH-006",
    "arbitrary-send-erc20": "ETH-006",
    # Logic
    "incorrect-equality": "ETH-034",
    "weak-prng": "ETH-037",
    "timestamp": "ETH-036",
    "boolean-cst": "ETH-075",
    # Token
    "unchecked-transfer": "ETH-022",
    "erc20-interface": "ETH-041",
    "locked-ether": "ETH-032",
    # Storage
    "uninitialized-state": "ETH-029",
    "uninitialized-storage": "ETH-029",
    "uninitialized-local": "ETH-029",
    "variable-scope": "ETH-031",
    "shadowing-state": "ETH-031",
    "shadowing-local": "ETH-031",
    "storage-array": "ETH-033",
    # Gas & DoS
    "calls-loop": "ETH-066",
    "costly-loop": "ETH-066",
    # Miscellaneous
    "pragma": "ETH-071",
    "solc-version": "ETH-072",
    "assembly": "ETH-012",
    "encode-packed-collision": "ETH-073",
    "rtlo": "ETH-074",
    "dead-code": "ETH-075",
    "missing-zero-check": "ETH-045",
    "missing-inheritance": "ETH-077",
    "write-after-write": "ETH-075",
    "unused-return": "ETH-018",
    "void-cst": "ETH-075",
    "constable-states": "ETH-076",
    "immutable-states": "ETH-076",
    "events-maths": "ETH-076",
    "events-access": "ETH-076",
}

# ── Aderyn detector name → ETH pattern ID mapping ───────────────────────────
ADERYN_TO_ETH = {
    "reentrancy": "ETH-001",
    "tx-origin": "ETH-007",
    "selfdestruct": "ETH-008",
    "delegatecall": "ETH-019",
    "unchecked-return": "ETH-018",
    "floating-pragma": "ETH-071",
    "outdated-solidity": "ETH-072",
    "abi-encode-packed": "ETH-073",
    "unsafe-erc20": "ETH-041",
    "missing-zero-address": "ETH-045",
    "unbounded-loop": "ETH-066",
    "weak-randomness": "ETH-037",
    "uninitialized-variable": "ETH-029",
    "shadowing": "ETH-031",
}

# ── Category → ETH prefix mapping for grouping ──────────────────────────────
CATEGORY_GROUP = {
    "reentrancy": "reentrancy",
    "access-control": "access-control",
    "arithmetic": "arithmetic",
    "external-calls": "external-calls",
    "oracle": "oracle",
    "storage": "storage",
    "logic": "logic",
    "token": "token",
    "proxy": "proxy",
    "defi": "defi",
    "gas-dos": "gas-dos",
    "miscellaneous": "miscellaneous",
    "transient-storage": "transient-storage",
    "input-validation": "input-validation",
}


def _normalize_eth_id(finding) -> str:
    """Extract or map a finding to its ETH-xxx pattern ID."""
    fid = finding.id if hasattr(finding, "id") else finding.get("id", "")

    # Already an ETH-xxx ID
    if fid.startswith("ETH-"):
        return fid.split("-")[0] + "-" + fid.split("-")[1][:3]  # ETH-001

    # Slither findings: SLITHER-<detector>
    if fid.startswith("SLITHER-"):
        detector = fid[len("SLITHER-"):]
        return SLITHER_TO_ETH.get(detector, "")

    # Aderyn findings
    if fid.startswith("ADERYN-"):
        detector = fid[len("ADERYN-"):]
        return ADERYN_TO_ETH.get(detector, "")

    return ""


def _get_attr(finding, attr, default=None):
    """Get attribute from Finding dataclass or dict."""
    if hasattr(finding, attr):
        return getattr(finding, attr)
    return finding.get(attr, default)


def _finding_key(finding) -> tuple:
    """Generate a grouping key: (file, line_bucket, eth_id_or_category).

    line_bucket groups lines within +-3 of each other.
    """
    file_path = _get_attr(finding, "file", "")
    line_num = _get_attr(finding, "line", 0)
    eth_id = _normalize_eth_id(finding)
    category = _get_attr(finding, "category", "unknown")

    # Use ETH ID if available, otherwise category
    pattern_key = eth_id if eth_id else category

    # Bucket lines: round to nearest 3
    line_bucket = (line_num // 3) * 3

    return (file_path, line_bucket, pattern_key)


def merge_findings(findings_lists: list) -> list:
    """Merge findings from multiple tool outputs.

    Groups by (file, line_range+-3, pattern). When multiple tools find the same
    vulnerability, keeps the most detailed finding and boosts confidence:
    - 2 tools agree: +10% confidence
    - 3+ tools agree: cap at 95%

    Args:
        findings_lists: List of finding lists, one per tool

    Returns:
        Deduplicated list of findings with boosted confidence
    """
    groups = {}

    for findings in findings_lists:
        for finding in findings:
            key = _finding_key(finding)
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)

    merged = []
    for key, group in groups.items():
        # Pick the finding with the longest description as primary
        primary = max(group, key=lambda f: len(_get_attr(f, "description", "")))

        tools = set()
        for f in group:
            tool = _get_attr(f, "tool", "unknown")
            tools.add(tool)

        base_confidence = _get_attr(primary, "confidence", 0.5)
        num_tools = len(tools)

        # Confidence boosting
        if num_tools >= 3:
            boosted_confidence = min(0.95, base_confidence + 0.15)
        elif num_tools == 2:
            boosted_confidence = min(0.95, base_confidence + 0.10)
        else:
            boosted_confidence = base_confidence

        # Update primary finding with boosted confidence
        if hasattr(primary, "confidence"):
            primary.confidence = boosted_confidence
            # Add tools_agreed as a dynamic attribute
            primary.tools_agreed = sorted(tools)
        else:
            primary["confidence"] = boosted_confidence
            primary["tools_agreed"] = sorted(tools)

        merged.append(primary)

    return merged


def filter_low_confidence(findings: list, threshold: float = 0.7) -> list:
    """Filter out findings below the confidence threshold.

    Args:
        findings: List of Finding objects or dicts
        threshold: Minimum confidence to keep (default 0.7)

    Returns:
        Filtered list with only findings >= threshold
    """
    return [f for f in findings if _get_attr(f, "confidence", 0) >= threshold]


def apply_context_filters(findings: list, content: str) -> list:
    """Filter false positives based on code context analysis.

    Checks for compensating controls that make flagged patterns safe:
    - Reentrancy findings where nonReentrant IS present in the function scope
    - Overflow findings in Solidity >= 0.8 without unchecked blocks
    - Missing access control where function actually has onlyOwner/onlyRole
    - SafeERC20 where safeTransfer IS used in the same scope

    Args:
        findings: List of Finding objects or dicts
        content: Full source code content to analyze

    Returns:
        Filtered list with false positives removed
    """
    if not content:
        return findings

    lines = content.split("\n")
    cl = content.lower()
    filtered = []

    # Detect pragma version
    pragma_m = re.search(r'pragma solidity\s*[\^>=<~]*\s*(0\.(\d+)\.\d+)', content)
    pragma_minor = int(pragma_m.group(2)) if pragma_m else 8

    for finding in findings:
        fid = _get_attr(finding, "id", "")
        line_num = _get_attr(finding, "line", 0)
        category = _get_attr(finding, "category", "")

        # ── Filter: Reentrancy with nonReentrant in function scope ──────
        if fid in ("ETH-001", "ETH-002", "ETH-003") or "reentrancy" in category:
            if _has_modifier_in_scope(lines, line_num, "nonReentrant"):
                continue

        # ── Filter: Overflow in Solidity >= 0.8 without unchecked ───────
        if fid == "ETH-013" and "Arithmetic Without Overflow" in _get_attr(finding, "title", ""):
            if pragma_minor >= 8:
                # In >= 0.8 only flag if inside unchecked block
                if not _is_in_unchecked_block(lines, line_num):
                    continue

        # ── Filter: Missing access control where modifier exists ────────
        if fid == "ETH-006" or (fid == "ETH-009" and "access-control" in category):
            if _has_modifier_in_scope(lines, line_num, "onlyOwner") or \
               _has_modifier_in_scope(lines, line_num, "onlyRole") or \
               _has_modifier_in_scope(lines, line_num, "onlyAdmin"):
                continue

        # ── Filter: SafeERC20 FP where safeTransfer IS used ────────────
        if fid in ("ETH-041", "ETH-022"):
            if "safetransfer(" in cl or "safetransferfrom(" in cl:
                # Check if the specific line actually uses the safe variant
                if line_num > 0 and line_num <= len(lines):
                    actual_line = lines[line_num - 1]
                    if "safeTransfer" in actual_line or "safeTransferFrom" in actual_line:
                        continue

        filtered.append(finding)

    return filtered


def _has_modifier_in_scope(lines: list, target_line: int, modifier: str) -> bool:
    """Check if a modifier exists in the function scope containing target_line.

    Looks backwards from target_line to find the function declaration and
    checks if the modifier is present on that function.
    """
    if target_line <= 0 or target_line > len(lines):
        return False

    # Search backwards for the function declaration
    for i in range(target_line - 1, max(0, target_line - 30), -1):
        line = lines[i]
        if re.search(r'\bfunction\s+\w+', line):
            # Check the function declaration line and next 2 lines for modifier
            for j in range(i, min(i + 3, len(lines))):
                if modifier in lines[j]:
                    return True
            return False
    return False


def _is_in_unchecked_block(lines: list, target_line: int) -> bool:
    """Check if target_line is inside an unchecked { } block."""
    if target_line <= 0 or target_line > len(lines):
        return False

    # Search backwards for unchecked {
    brace_depth = 0
    for i in range(target_line - 1, max(0, target_line - 20), -1):
        line = lines[i]
        brace_depth += line.count("}") - line.count("{")
        if "unchecked" in line and "{" in line:
            if brace_depth <= 0:
                return True
    return False


def normalize_slither_findings(slither_findings: list) -> list:
    """Normalize Slither findings by mapping detector names to ETH-xxx IDs.

    Args:
        slither_findings: Raw findings from run_slither()

    Returns:
        Findings with normalized ETH IDs where mapping exists
    """
    for finding in slither_findings:
        fid = _get_attr(finding, "id", "")
        if fid.startswith("SLITHER-"):
            detector = fid[len("SLITHER-"):]
            eth_id = SLITHER_TO_ETH.get(detector)
            if eth_id:
                if hasattr(finding, "id"):
                    finding.id = eth_id
                else:
                    finding["id"] = eth_id
    return slither_findings
