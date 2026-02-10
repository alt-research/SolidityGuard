"""Wrapper around the core solidity_guard.py scanner."""

import sys
from pathlib import Path
from typing import Optional

from solidityguard.config import get_scripts_dir


def _ensure_scanner_importable():
    """Add scanner scripts directory to sys.path if needed."""
    scripts_dir = str(get_scripts_dir())
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)


def scan(target_path: str, category: Optional[str] = None, pattern: Optional[str] = None) -> list:
    """Run the pattern scanner and return findings.

    Args:
        target_path: Path to contracts directory.
        category: Optional category filter (e.g. 'reentrancy').
        pattern: Optional specific pattern ID filter (e.g. 'ETH-001').

    Returns:
        List of Finding dataclass instances from solidity_guard.
    """
    _ensure_scanner_importable()
    from solidity_guard import scan_patterns

    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    findings = scan_patterns(str(target))

    # Apply filters
    if pattern:
        pattern_upper = pattern.upper()
        findings = [f for f in findings if f.id == pattern_upper]
    elif category:
        cat_lower = category.lower()
        findings = [f for f in findings if f.category == cat_lower]

    return findings


def run_slither(target_path: str) -> list:
    """Run Slither static analysis and return findings.

    Delegates to solidity_guard.run_slither() which handles subprocess
    execution and result parsing.

    Returns:
        List of Finding dataclass instances from Slither.
    """
    _ensure_scanner_importable()
    from solidity_guard import run_slither as _run_slither

    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    return _run_slither(str(target))


def run_aderyn(target_path: str) -> list:
    """Run Aderyn static analysis and return findings.

    Delegates to solidity_guard.run_aderyn() which handles subprocess
    execution and result parsing.

    Returns:
        List of Finding dataclass instances from Aderyn.
    """
    _ensure_scanner_importable()
    from solidity_guard import run_aderyn as _run_aderyn

    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    return _run_aderyn(str(target))


def deduplicate_findings(findings: list) -> list:
    """Remove duplicate findings that match on file + line + severity.

    When multiple tools find the same issue, keep the one with higher
    confidence. Findings without a file/line are never considered duplicates.

    Returns:
        Deduplicated list of Finding instances.
    """
    seen = {}
    for f in findings:
        if not f.file or not f.line:
            key = id(f)  # unique — never dedup findings without location
        else:
            key = (f.file, f.line, f.severity)

        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f

    return list(seen.values())


def count_solidity_files(target_path: str) -> tuple[int, int]:
    """Count .sol files and total lines in a directory.

    Returns:
        (file_count, line_count)
    """
    target = Path(target_path)
    if not target.exists():
        return 0, 0

    files = list(target.rglob("*.sol"))
    total_lines = 0
    for f in files:
        try:
            total_lines += len(f.read_text().splitlines())
        except Exception:
            pass
    return len(files), total_lines


def calculate_score(findings: list) -> dict:
    """Calculate security score from findings.

    Returns:
        Dict with severity counts and score.
    """
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    info = sum(1 for f in findings if f.severity == "INFORMATIONAL")

    score = max(0, 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1))

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "informational": info,
        "total": len(findings),
        "score": score,
    }
