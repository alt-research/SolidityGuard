#!/usr/bin/env python3
"""
SolidityGuard CLI Integration Tests

Tests for the Click CLI commands using CliRunner.

Usage:
    python3 -m pytest test_cli.py -v
    python3 test_cli.py
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the CLI package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from click.testing import CliRunner

from solidityguard.cli import cli


class TestCLIAudit(unittest.TestCase):
    """Tests for the 'audit' command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_audit_quick_with_vuln_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    function check() external {
        require(tx.origin == msg.sender, "EOA only");
    }
}
""")
            result = self.runner.invoke(cli, ["audit", tmpdir, "--quick"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Pattern Scanner", result.output)

    def test_audit_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(cli, ["audit", tmpdir, "--quick"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No .sol files", result.output)

    def test_audit_with_json_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
""")
            output_file = os.path.join(tmpdir, "results.json")
            result = self.runner.invoke(cli, [
                "audit", tmpdir, "--quick", "-o", output_file,
            ])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(os.path.exists(output_file))
            data = json.loads(Path(output_file).read_text())
            self.assertIn("findings", data)
            self.assertIn("summary", data)

    def test_audit_nonexistent_path(self):
        result = self.runner.invoke(cli, ["audit", "/nonexistent/path", "--quick"])
        self.assertNotEqual(result.exit_code, 0)


class TestCLIScan(unittest.TestCase):
    """Tests for the 'scan' command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_scan_all_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    function check() external {
        require(tx.origin == msg.sender, "EOA only");
    }
}
""")
            result = self.runner.invoke(cli, ["scan", tmpdir])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Filter: all patterns", result.output)

    def test_scan_with_category_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    function check() external {
        require(tx.origin == msg.sender, "EOA only");
    }
}
""")
            result = self.runner.invoke(cli, ["scan", tmpdir, "-c", "access-control"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("access-control", result.output)

    def test_scan_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(cli, ["scan", tmpdir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No .sol files", result.output)


class TestCLIPatterns(unittest.TestCase):
    """Tests for the 'patterns' command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_patterns_list(self):
        result = self.runner.invoke(cli, ["patterns"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("104 patterns", result.output)

    def test_patterns_with_category(self):
        result = self.runner.invoke(cli, ["patterns", "-c", "reentrancy"])
        self.assertEqual(result.exit_code, 0, result.output)


class TestCLITools(unittest.TestCase):
    """Tests for the 'tools' command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_tools_check(self):
        result = self.runner.invoke(cli, ["tools"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Pattern Scanner may be split across table lines in rich output
        self.assertTrue(
            "Pattern Scanner" in result.output or "Pattern" in result.output,
            "Expected 'Pattern' in tools output",
        )
        self.assertIn("tools available", result.output)


class TestCLIVersion(unittest.TestCase):
    """Tests for the 'version' command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_version(self):
        result = self.runner.invoke(cli, ["version"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("1.3.1", result.output)
        self.assertIn("104", result.output)


class TestCLIEvmbench(unittest.TestCase):
    """Tests for the 'evmbench' command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_evmbench_help(self):
        result = self.runner.invoke(cli, ["evmbench", "--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("EVMBench", result.output)
        self.assertIn("detect", result.output)
        self.assertIn("exploit", result.output)
        self.assertIn("patch", result.output)


if __name__ == "__main__":
    unittest.main()
