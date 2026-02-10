#!/usr/bin/env python3
"""
SolidityGuard Integration Test Suite

Tests for the full scan pipeline, finding merger, context filters,
run_full_scan(), and cross-tool verification.

Usage:
    python3 -m pytest test_integration.py -v
    python3 test_integration.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from solidity_guard import Finding, ScanResults, scan_patterns, run_full_scan
from finding_merger import (
    merge_findings,
    filter_low_confidence,
    apply_context_filters,
    normalize_slither_findings,
    SLITHER_TO_ETH,
    ADERYN_TO_ETH,
    _has_modifier_in_scope,
    _is_in_unchecked_block,
)


# ── Helper ───────────────────────────────────────────────────────────────────

def _make_finding(**kwargs):
    defaults = dict(
        id="ETH-001", title="Test", severity="HIGH", confidence=0.80,
        file="test.sol", line=10, code_snippet="", description="desc",
        recommendation="rec", category="reentrancy", tool="pattern-scanner",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── Merge Findings Tests ─────────────────────────────────────────────────────

class TestMergeFindings(unittest.TestCase):

    def test_single_tool_no_boost(self):
        f = _make_finding(confidence=0.80)
        merged = merge_findings([[f]])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].confidence, 0.80)

    def test_two_tools_boost_10_percent(self):
        f1 = _make_finding(tool="pattern-scanner", confidence=0.80)
        f2 = _make_finding(tool="slither", confidence=0.75)
        merged = merge_findings([[f1], [f2]])
        self.assertEqual(len(merged), 1)
        self.assertAlmostEqual(merged[0].confidence, 0.90)  # 0.80 + 0.10
        self.assertEqual(set(merged[0].tools_agreed), {"pattern-scanner", "slither"})

    def test_three_tools_cap_at_95(self):
        f1 = _make_finding(tool="pattern-scanner", confidence=0.85)
        f2 = _make_finding(tool="slither", confidence=0.80)
        f3 = _make_finding(tool="aderyn", confidence=0.75)
        merged = merge_findings([[f1], [f2], [f3]])
        self.assertEqual(len(merged), 1)
        self.assertAlmostEqual(merged[0].confidence, 0.95)  # cap

    def test_different_files_not_merged(self):
        f1 = _make_finding(file="a.sol", line=10)
        f2 = _make_finding(file="b.sol", line=10)
        merged = merge_findings([[f1], [f2]])
        self.assertEqual(len(merged), 2)

    def test_different_patterns_not_merged(self):
        f1 = _make_finding(id="ETH-001", category="reentrancy")
        f2 = _make_finding(id="ETH-007", category="access-control")
        merged = merge_findings([[f1, f2]])
        self.assertEqual(len(merged), 2)

    def test_nearby_lines_merged(self):
        """Lines within +-3 should be grouped together."""
        f1 = _make_finding(line=10, tool="pattern-scanner")
        f2 = _make_finding(line=11, tool="slither")
        merged = merge_findings([[f1], [f2]])
        self.assertEqual(len(merged), 1)  # lines 10 and 11 in same bucket

    def test_distant_lines_not_merged(self):
        """Lines far apart should not be merged."""
        f1 = _make_finding(line=10, tool="pattern-scanner")
        f2 = _make_finding(line=50, tool="slither")
        merged = merge_findings([[f1], [f2]])
        self.assertEqual(len(merged), 2)

    def test_keeps_longest_description(self):
        f1 = _make_finding(tool="a", description="short")
        f2 = _make_finding(tool="b", description="this is a much longer description with details")
        merged = merge_findings([[f1], [f2]])
        self.assertEqual(len(merged), 1)
        self.assertIn("much longer", merged[0].description)

    def test_empty_inputs(self):
        self.assertEqual(merge_findings([]), [])
        self.assertEqual(merge_findings([[], []]), [])


# ── Filter Low Confidence Tests ──────────────────────────────────────────────

class TestFilterLowConfidence(unittest.TestCase):

    def test_filters_below_threshold(self):
        findings = [
            _make_finding(confidence=0.50),
            _make_finding(id="ETH-007", confidence=0.80),
        ]
        result = filter_low_confidence(findings, threshold=0.7)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "ETH-007")

    def test_keeps_at_threshold(self):
        f = _make_finding(confidence=0.70)
        result = filter_low_confidence([f], threshold=0.7)
        self.assertEqual(len(result), 1)

    def test_custom_threshold(self):
        findings = [_make_finding(confidence=0.60)]
        self.assertEqual(len(filter_low_confidence(findings, threshold=0.5)), 1)
        self.assertEqual(len(filter_low_confidence(findings, threshold=0.65)), 0)

    def test_empty_list(self):
        self.assertEqual(filter_low_confidence([], threshold=0.7), [])


# ── Context Filters Tests ────────────────────────────────────────────────────

class TestApplyContextFilters(unittest.TestCase):

    def test_filters_reentrancy_with_nonReentrant(self):
        code = """pragma solidity 0.8.20;
contract Test {
    function withdraw() external nonReentrant {
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}"""
        f = _make_finding(id="ETH-001", line=4, category="reentrancy")
        result = apply_context_filters([f], code)
        self.assertEqual(len(result), 0)

    def test_keeps_reentrancy_without_guard(self):
        code = """pragma solidity 0.8.20;
contract Test {
    function withdraw() external {
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}"""
        f = _make_finding(id="ETH-001", line=4, category="reentrancy")
        result = apply_context_filters([f], code)
        self.assertEqual(len(result), 1)

    def test_filters_access_control_with_onlyOwner(self):
        code = """pragma solidity 0.8.20;
contract Test {
    function setPrice(uint p) external onlyOwner {
        price = p;
    }
}"""
        f = _make_finding(id="ETH-006", line=4, category="access-control")
        result = apply_context_filters([f], code)
        self.assertEqual(len(result), 0)

    def test_keeps_access_control_without_modifier(self):
        code = """pragma solidity 0.8.20;
contract Test {
    function setPrice(uint p) external {
        price = p;
    }
}"""
        f = _make_finding(id="ETH-006", line=4, category="access-control")
        result = apply_context_filters([f], code)
        self.assertEqual(len(result), 1)

    def test_empty_content_returns_all(self):
        f = _make_finding()
        result = apply_context_filters([f], "")
        self.assertEqual(len(result), 1)

    def test_non_reentrancy_finding_unchanged(self):
        code = """pragma solidity 0.8.20;
contract Test {
    function withdraw() external nonReentrant {
        selfdestruct(payable(msg.sender));
    }
}"""
        f = _make_finding(id="ETH-008", line=4, category="access-control")
        result = apply_context_filters([f], code)
        self.assertEqual(len(result), 1)  # selfdestruct not affected by nonReentrant filter


# ── Helper Function Tests ────────────────────────────────────────────────────

class TestHelperFunctions(unittest.TestCase):

    def test_has_modifier_in_scope_true(self):
        lines = [
            "contract Test {",
            "    function withdraw() external nonReentrant {",
            "        msg.sender.call{value: amount}(\"\");",
            "    }",
            "}",
        ]
        self.assertTrue(_has_modifier_in_scope(lines, 3, "nonReentrant"))

    def test_has_modifier_in_scope_false(self):
        lines = [
            "contract Test {",
            "    function withdraw() external {",
            "        msg.sender.call{value: amount}(\"\");",
            "    }",
            "}",
        ]
        self.assertFalse(_has_modifier_in_scope(lines, 3, "nonReentrant"))

    def test_is_in_unchecked_block_true(self):
        lines = [
            "function test() external {",
            "    unchecked {",
            "        x = a + b;",
            "    }",
            "}",
        ]
        self.assertTrue(_is_in_unchecked_block(lines, 3))

    def test_is_in_unchecked_block_false(self):
        lines = [
            "function test() external {",
            "    x = a + b;",
            "}",
        ]
        self.assertFalse(_is_in_unchecked_block(lines, 2))

    def test_out_of_bounds_line(self):
        lines = ["line 1", "line 2"]
        self.assertFalse(_has_modifier_in_scope(lines, 100, "nonReentrant"))
        self.assertFalse(_is_in_unchecked_block(lines, 0))


# ── Normalize Slither Findings Tests ─────────────────────────────────────────

class TestNormalizeSlitherFindings(unittest.TestCase):

    def test_maps_known_detector(self):
        f = _make_finding(id="SLITHER-reentrancy-eth", tool="slither")
        result = normalize_slither_findings([f])
        self.assertEqual(result[0].id, "ETH-001")

    def test_preserves_unmapped_detector(self):
        f = _make_finding(id="SLITHER-unknown-detector", tool="slither")
        result = normalize_slither_findings([f])
        self.assertEqual(result[0].id, "SLITHER-unknown-detector")

    def test_preserves_eth_id(self):
        f = _make_finding(id="ETH-007")
        result = normalize_slither_findings([f])
        self.assertEqual(result[0].id, "ETH-007")

    def test_all_slither_mappings_have_eth_prefix(self):
        for detector, eth_id in SLITHER_TO_ETH.items():
            self.assertTrue(eth_id.startswith("ETH-"), f"{detector} -> {eth_id}")

    def test_all_aderyn_mappings_have_eth_prefix(self):
        for detector, eth_id in ADERYN_TO_ETH.items():
            self.assertTrue(eth_id.startswith("ETH-"), f"{detector} -> {eth_id}")


# ── Mapping Coverage Tests ───────────────────────────────────────────────────

class TestMappingCoverage(unittest.TestCase):

    def test_slither_minimum_coverage(self):
        self.assertGreaterEqual(len(SLITHER_TO_ETH), 30)

    def test_aderyn_minimum_coverage(self):
        self.assertGreaterEqual(len(ADERYN_TO_ETH), 10)

    def test_slither_key_detectors_mapped(self):
        key_detectors = [
            "reentrancy-eth", "tx-origin", "suicidal",
            "controlled-delegatecall", "unchecked-lowlevel",
            "incorrect-equality", "pragma", "solc-version",
        ]
        for d in key_detectors:
            self.assertIn(d, SLITHER_TO_ETH, f"Missing Slither mapping: {d}")


# ── Full Scan Pipeline Tests ─────────────────────────────────────────────────

class TestFullScanPipeline(unittest.TestCase):

    def test_scan_patterns_returns_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    function check() external {
        require(tx.origin == owner, "Not owner");
    }
}
""")
            findings = scan_patterns(tmpdir)
            self.assertTrue(len(findings) > 0)
            for f in findings:
                self.assertIsInstance(f.id, str)
                self.assertIsInstance(f.severity, str)
                self.assertIsInstance(f.confidence, float)
                self.assertTrue(f.file)
                self.assertTrue(f.line > 0)

    def test_scan_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan_patterns(tmpdir)
            self.assertEqual(len(findings), 0)

    def test_scan_no_sol_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "readme.txt").write_text("not solidity")
            findings = scan_patterns(tmpdir)
            self.assertEqual(len(findings), 0)

    def test_run_full_scan_patterns_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    function check() external {
        require(tx.origin == owner, "Not owner");
    }
}
""")
            results = run_full_scan(tmpdir, tools=["patterns"])
            self.assertTrue(len(results) > 0)
            ids = [f.id for f in results]
            self.assertTrue("ETH-007" in ids or "ETH-086" in ids)

    def test_run_full_scan_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = run_full_scan(tmpdir, tools=["patterns"])
            self.assertEqual(len(results), 0)

    def test_run_full_scan_filters_low_confidence(self):
        """Findings with confidence < 0.7 should be filtered out."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    uint private mySecret;
}
""")
            results = run_full_scan(tmpdir, tools=["patterns"])
            for f in results:
                self.assertGreaterEqual(f.confidence, 0.7,
                    f"Finding {f.id} has confidence {f.confidence} < 0.7")

    def test_full_pipeline_multi_vuln(self):
        """Test full pipeline with a contract containing multiple vulns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Vault.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract InsecureVault {
    mapping(address => uint) public balances;

    function deposit() external payable {
        unchecked { balances[msg.sender] += msg.value; }
    }

    function withdraw(uint amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
""")
            results = run_full_scan(tmpdir, tools=["patterns"])
            # Should find multiple issues (some may be filtered by confidence)
            self.assertTrue(len(results) >= 2, f"Expected >= 2 findings, got {len(results)}")


# ── Finding Dataclass Tests ──────────────────────────────────────────────────

class TestFindingDataclass(unittest.TestCase):

    def test_all_fields_present(self):
        f = _make_finding()
        d = f.to_dict()
        expected_keys = {"id", "title", "severity", "confidence", "file",
                         "line", "code_snippet", "description",
                         "recommendation", "category", "swc", "tool"}
        self.assertEqual(set(d.keys()), expected_keys)

    def test_default_tool(self):
        f = Finding(id="ETH-001", title="T", severity="HIGH", confidence=0.5,
                    file="a.sol", line=1, code_snippet="", description="",
                    recommendation="", category="test")
        self.assertEqual(f.tool, "manual")

    def test_swc_optional(self):
        f = _make_finding(swc=None)
        self.assertIsNone(f.swc)
        f2 = _make_finding(swc="SWC-107")
        self.assertEqual(f2.swc, "SWC-107")


# ── ScanResults Tests ────────────────────────────────────────────────────────

class TestScanResultsIntegration(unittest.TestCase):

    def test_to_dict_structure(self):
        results = ScanResults(
            project="Test",
            timestamp="2026-01-01T00:00:00",
            tools_used=["slither", "patterns"],
        )
        results.add_finding(_make_finding(severity="CRITICAL"))
        results.add_finding(_make_finding(severity="HIGH"))
        results.calculate_score()

        d = results.to_dict()
        self.assertIn("project", d)
        self.assertIn("findings", d)
        self.assertIn("summary", d)
        self.assertIn("security_score", d)
        self.assertEqual(len(d["findings"]), 2)

    def test_score_with_mixed_severities(self):
        results = ScanResults(
            project="Test",
            timestamp="2026-01-01T00:00:00",
            tools_used=["patterns"],
        )
        results.add_finding(_make_finding(severity="CRITICAL"))
        results.add_finding(_make_finding(severity="HIGH"))
        results.add_finding(_make_finding(severity="MEDIUM"))
        results.add_finding(_make_finding(severity="LOW"))
        results.calculate_score()
        # 100 - 15 - 8 - 3 - 1 = 73
        self.assertEqual(results.security_score, 73)


if __name__ == "__main__":
    unittest.main()
