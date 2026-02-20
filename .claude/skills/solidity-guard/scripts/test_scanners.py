#!/usr/bin/env python3
"""
SolidityGuard Scanner Test Suite

Tests for the vulnerability scanner, report generator, and finding verifier.

Usage:
    python3 -m pytest test_scanners.py -v
    python3 test_scanners.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from solidity_guard import Finding, ScanResults, scan_patterns
from report_generator import generate_report
from verify_findings import generate_verification_prompts


class TestFinding(unittest.TestCase):
    def test_finding_creation(self):
        f = Finding(
            id="ETH-001",
            title="Reentrancy",
            severity="CRITICAL",
            confidence=0.95,
            file="contracts/Vault.sol",
            line=45,
            code_snippet="msg.sender.call{value: amount}('')",
            description="Reentrancy vulnerability",
            recommendation="Use nonReentrant modifier",
            category="reentrancy",
            swc="SWC-107",
            tool="slither",
        )
        self.assertEqual(f.id, "ETH-001")
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.confidence, 0.95)

    def test_finding_to_dict(self):
        f = Finding(
            id="ETH-006",
            title="Missing Access Control",
            severity="CRITICAL",
            confidence=0.85,
            file="contracts/Admin.sol",
            line=20,
            code_snippet="function setPrice(uint p) external { price = p; }",
            description="No access control",
            recommendation="Add onlyOwner",
            category="access-control",
        )
        d = f.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["id"], "ETH-006")


class TestScanResults(unittest.TestCase):
    def test_empty_results(self):
        results = ScanResults(
            project="TestProject",
            timestamp="2026-01-01T00:00:00",
            tools_used=["slither"],
        )
        results.calculate_score()
        self.assertEqual(results.security_score, 100)
        self.assertEqual(results.summary["total"], 0)

    def test_score_calculation(self):
        results = ScanResults(
            project="TestProject",
            timestamp="2026-01-01T00:00:00",
            tools_used=["slither"],
        )
        results.add_finding(Finding(
            id="ETH-001", title="Reentrancy", severity="CRITICAL",
            confidence=0.95, file="test.sol", line=1,
            code_snippet="", description="", recommendation="",
            category="reentrancy",
        ))
        results.add_finding(Finding(
            id="ETH-013", title="Overflow", severity="HIGH",
            confidence=0.80, file="test.sol", line=2,
            code_snippet="", description="", recommendation="",
            category="arithmetic",
        ))
        results.calculate_score()
        # 100 - 15 (critical) - 8 (high) = 77
        self.assertEqual(results.security_score, 77)
        self.assertEqual(results.summary["critical"], 1)
        self.assertEqual(results.summary["high"], 1)

    def test_minimum_score(self):
        results = ScanResults(
            project="TestProject",
            timestamp="2026-01-01T00:00:00",
            tools_used=["slither"],
        )
        # Add 10 critical findings
        for i in range(10):
            results.add_finding(Finding(
                id=f"ETH-{i:03d}", title=f"Critical {i}", severity="CRITICAL",
                confidence=0.95, file="test.sol", line=i,
                code_snippet="", description="", recommendation="",
                category="test",
            ))
        results.calculate_score()
        self.assertEqual(results.security_score, 0)  # Floor at 0


class TestPatternScanner(unittest.TestCase):
    def test_detect_tx_origin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Test {
    address owner;
    function check() external {
        require(tx.origin == owner, "Not owner");
    }
}
""")
            findings = scan_patterns(tmpdir)
            tx_origin = [f for f in findings if f.id == "ETH-007"]
            self.assertTrue(len(tx_origin) > 0)

    def test_detect_floating_pragma(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("pragma solidity ^0.8.0;\ncontract Test {}")
            findings = scan_patterns(tmpdir)
            floating = [f for f in findings if f.id == "ETH-071"]
            self.assertTrue(len(floating) > 0)

    def test_detect_selfdestruct(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
""")
            findings = scan_patterns(tmpdir)
            sd = [f for f in findings if f.id == "ETH-008"]
            self.assertTrue(len(sd) > 0)


    def test_detect_eip7702_txorigin_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    modifier onlyEOA() {
        require(tx.origin == msg.sender, "No contracts");
        _;
    }
}
""")
            findings = scan_patterns(tmpdir)
            eip7702 = [f for f in findings if f.id == "ETH-086"]
            self.assertTrue(len(eip7702) > 0)

    def test_detect_extcodesize(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
""")
            findings = scan_patterns(tmpdir)
            eoa = [f for f in findings if f.id == "ETH-089"]
            self.assertTrue(len(eoa) > 0)


class TestCTFReentrancy(unittest.TestCase):
    """CTF: Reentrancy patterns from Ethernaut L10, DVDeFi, DeFiVulnLabs."""

    def test_eth013_unchecked_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    function unsafeAdd(uint a, uint b) external pure returns (uint) {
        unchecked { return a + b; }
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-013"]
            self.assertTrue(len(hits) > 0, "Should detect unchecked arithmetic block")


class TestCTFAccessControl(unittest.TestCase):
    """CTF: Access control patterns from Ethernaut L1/L6, ONLYPWNER."""

    def test_eth019_delegatecall(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    address public impl;
    fallback() external payable {
        (bool s, ) = impl.delegatecall(msg.data);
        require(s);
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-019"]
            self.assertTrue(len(hits) > 0, "Should detect delegatecall usage")


class TestCTFExternalCalls(unittest.TestCase):
    """CTF: External call patterns from Ethernaut L31, DeFiVulnLabs."""

    def test_eth079_transfer_send(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-079"]
            self.assertTrue(len(hits) > 0, "Should detect .transfer() hardcoded gas")

    def test_eth073_abi_encodepacked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    function hash(string memory a, string memory b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-073"]
            self.assertTrue(len(hits) > 0, "Should detect abi.encodePacked hash collision risk")


class TestCTFOracle(unittest.TestCase):
    """CTF: Oracle patterns from DVDeFi Puppet, DeFiVulnLabs."""

    def test_eth037_weak_randomness(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Lottery {
    function random() external view returns (uint) {
        uint seed = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
        return seed % 100;
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-037"]
            self.assertTrue(len(hits) > 0, "Should detect weak randomness from block.timestamp")


class TestCTFGasDoS(unittest.TestCase):
    """CTF: Gas/DoS patterns from Ethernaut L9/L20, DeFiVulnLabs."""

    def test_eth066_unbounded_loop(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    address[] public users;
    function distributeAll() external {
        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-066"]
            self.assertTrue(len(hits) > 0, "Should detect unbounded loop over dynamic array")


class TestCTFMisc(unittest.TestCase):
    """CTF: Miscellaneous patterns from Ethernaut, Capture the Ether."""

    def test_eth072_outdated_compiler(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.6.12;
contract Test {
    uint public value;
    function set(uint v) external { value = v; }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-072"]
            self.assertTrue(len(hits) > 0, "Should detect outdated Solidity version")

    def test_eth008_selfdestruct_in_impl(self):
        """Ethernaut L25: selfdestruct in UUPS implementation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Implementation {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-008"]
            self.assertTrue(len(hits) > 0, "Should detect selfdestruct in implementation")


class TestCTFProxy(unittest.TestCase):
    """CTF: Proxy/upgrade patterns including ETH-049."""

    def test_eth049_missing_disable_initializers(self):
        """ETH-049 should fire when Initializable contract has no _disableInitializers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract Vulnerable is Initializable {
    uint public value;
    function initialize(uint v) public initializer {
        value = v;
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-049"]
            self.assertTrue(len(hits) > 0, "Should detect missing _disableInitializers")

    def test_eth049_no_false_positive_with_disable_initializers(self):
        """ETH-049 should NOT fire when constructor calls _disableInitializers (Issue #3)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract Safe is Initializable {
    uint public value;
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    function initialize(uint v) public initializer {
        value = v;
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-049"]
            self.assertEqual(len(hits), 0, "Should NOT flag ETH-049 when _disableInitializers is called in constructor")


class TestCTFTransientStorage(unittest.TestCase):
    """CTF: EIP-1153 transient storage patterns from SIR.trading exploit."""

    def test_eth081_tstore_hardcoded_slot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.24;
contract Lock {
    function lock() internal {
        assembly { tstore(0x01, 1) }
    }
    function unlock() internal {
        assembly { tstore(0x01, 0) }
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-081"]
            self.assertTrue(len(hits) > 0, "Should detect hardcoded TSTORE slot collision risk")


class TestCTFInputValidation(unittest.TestCase):
    """CTF: OWASP 2025 #4 Input Validation patterns."""

    def test_eth098_missing_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Test {
    mapping(address => uint) public balances;
    function withdraw(uint amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-098"]
            self.assertTrue(len(hits) > 0, "Should detect missing input validation on external function")


class TestCTFCombined(unittest.TestCase):
    """CTF: Multi-vulnerability contracts (like real audits)."""

    def test_multi_vuln_contract(self):
        """Contract with multiple vulnerabilities - simulates DVDeFi challenge."""
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
            findings = scan_patterns(tmpdir)
            ids = {f.id for f in findings}
            self.assertIn("ETH-071", ids, "Should detect floating pragma")
            self.assertIn("ETH-013", ids, "Should detect unchecked block")
            self.assertIn("ETH-008", ids, "Should detect selfdestruct")
            self.assertIn("ETH-079", ids, "Should detect .transfer()")
            self.assertTrue(len(findings) >= 4, f"Should find at least 4 issues, found {len(findings)}")

    def test_defi_vuln_contract(self):
        """DeFi-style contract with oracle and access control issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "DeFi.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract VulnDeFi {
    address public admin;
    uint public price;

    function setPrice(uint newPrice) external {
        price = newPrice;
    }

    function swap(uint amount) external {
        uint out = amount * price / 1e18;
        payable(msg.sender).transfer(out);
    }

    function emergencyWithdraw(address to) external {
        (bool s, ) = to.delegatecall(abi.encodeWithSignature("drain()"));
    }
}
""")
            findings = scan_patterns(tmpdir)
            ids = {f.id for f in findings}
            self.assertIn("ETH-019", ids, "Should detect delegatecall")
            self.assertIn("ETH-079", ids, "Should detect .transfer()")


class TestParadigmCTFPatterns(unittest.TestCase):
    """Paradigm CTF: Patterns derived from 2021/2022/2023 challenges."""

    def test_eth024_getreserves_oracle(self):
        """Paradigm 2021/broker: getReserves() used for rate calculation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
contract Broker {
    IUniswapV2Pair pair;
    function rate() public view returns (uint256) {
        (uint112 _reserve0, uint112 _reserve1, ) = pair.getReserves();
        return uint256(_reserve0) * 1e18 / uint256(_reserve1);
    }
    function liquidate(address user, uint256 amount) external {
        uint256 price = rate();
        require(amount * price / 1e18 > 0);
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-024"]
            self.assertTrue(len(hits) > 0, "Should detect oracle manipulation via getReserves()")

    def test_eth027_multiline_swap_zero_slippage(self):
        """Paradigm 2021/farmer: multi-line swapExactTokensForTokens with 0 amountOutMin."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
interface UniRouter {
    function swapExactTokensForTokens(
        uint amountIn, uint amountOutMin, address[] calldata path,
        address to, uint deadline
    ) external returns (uint[] memory);
}
contract Farmer {
    UniRouter public router;
    function recycle() public returns (uint256) {
        address[] memory path = new address[](3);
        uint256[] memory amts = router.swapExactTokensForTokens(
            100,
            0,
            path,
            address(this),
            block.timestamp + 1800
        );
        return amts[2];
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-027"]
            self.assertTrue(len(hits) > 0, "Should detect zero slippage in multi-line swap call")

    def test_eth034_balanceof_strict_equality(self):
        """Paradigm 2023/dodont: balanceOf(x) == 0 strict equality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}
contract DoDont {
    IERC20 token;
    function check(address user) external view returns (bool) {
        return token.balanceOf(user) == 0;
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-034"]
            self.assertTrue(len(hits) > 0, "Should detect strict equality on balanceOf")

    def test_eth037_pure_random_function(self):
        """Paradigm 2022/random: pure function named random is deterministic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text("""
pragma solidity 0.8.20;
contract Random {
    function random() external pure returns (uint256) {
        return 4;
    }
}
""")
            findings = scan_patterns(tmpdir)
            hits = [f for f in findings if f.id == "ETH-037"]
            self.assertTrue(len(hits) > 0, "Should detect pure 'random' function as predictable")


class TestReportGenerator(unittest.TestCase):
    def test_generate_empty_report(self):
        data = {
            "project": "Test",
            "timestamp": "2026-01-01T00:00:00",
            "tools_used": ["slither"],
            "findings": [],
            "summary": {
                "critical": 0, "high": 0, "medium": 0,
                "low": 0, "informational": 0, "total": 0,
            },
            "security_score": 100,
        }
        report = generate_report(data)
        self.assertIn("Security Audit Report", report)
        self.assertIn("100/100", report)

    def test_generate_report_with_findings(self):
        data = {
            "project": "VaultProtocol",
            "timestamp": "2026-01-01T00:00:00",
            "tools_used": ["slither", "aderyn"],
            "findings": [{
                "id": "ETH-001",
                "title": "Reentrancy",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "file": "contracts/Vault.sol",
                "line": 45,
                "code_snippet": "msg.sender.call{value: amount}('')",
                "description": "State update after external call",
                "recommendation": "Apply CEI pattern",
                "category": "reentrancy",
                "swc": "SWC-107",
                "tool": "slither",
            }],
            "summary": {
                "critical": 1, "high": 0, "medium": 0,
                "low": 0, "informational": 0, "total": 1,
            },
            "security_score": 85,
        }
        report = generate_report(data, project="VaultProtocol")
        self.assertIn("VaultProtocol", report)
        self.assertIn("ETH-001", report)
        self.assertIn("Reentrancy", report)
        self.assertIn("85/100", report)


class TestFindingVerifier(unittest.TestCase):
    def test_generate_prompts(self):
        data = {
            "findings": [{
                "id": "ETH-001",
                "title": "Reentrancy",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "file": "contracts/Vault.sol",
                "line": 45,
                "description": "State update after external call",
                "tool": "slither",
            }]
        }
        prompts = generate_verification_prompts(data, ["CRITICAL"])
        self.assertEqual(len(prompts), 1)
        self.assertIn("ETH-001", prompts[0]["prompt"])

    def test_severity_filter(self):
        data = {
            "findings": [
                {"id": "ETH-001", "severity": "CRITICAL", "title": "A",
                 "confidence": 0.9, "file": "a.sol", "line": 1, "description": "", "tool": "s"},
                {"id": "ETH-071", "severity": "LOW", "title": "B",
                 "confidence": 0.9, "file": "b.sol", "line": 1, "description": "", "tool": "s"},
            ]
        }
        prompts = generate_verification_prompts(data, ["CRITICAL"])
        self.assertEqual(len(prompts), 1)


class TestIntegrationFullScan(unittest.TestCase):
    """Integration tests for the full scan pipeline."""

    def test_full_scan_pipeline(self):
        """Create a temp dir with vulnerable .sol, run scan_patterns(), verify findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Vulnerable.sol"
            sol_file.write_text("""
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint) public balances;

    function deposit() external payable {
        unchecked { balances[msg.sender] += msg.value; }
    }

    function withdraw(uint amount) external {
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed");
        balances[msg.sender] -= amount;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
""")
            findings = scan_patterns(tmpdir)
            self.assertIsInstance(findings, list)
            self.assertTrue(len(findings) >= 3, f"Expected >= 3 findings, got {len(findings)}")
            # Verify findings have correct fields
            for f in findings:
                self.assertIsNotNone(f.id)
                self.assertIsNotNone(f.severity)
                self.assertIsNotNone(f.file)
                self.assertTrue(f.line >= 0)
                self.assertTrue(0.0 < f.confidence <= 1.0)

    def test_scan_empty_dir(self):
        """Empty dir returns empty findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan_patterns(tmpdir)
            self.assertEqual(findings, [])

    def test_scan_nonexistent_dir(self):
        """Nonexistent dir returns empty findings (no crash)."""
        findings = scan_patterns("/tmp/nonexistent_dir_solidityguard_test")
        self.assertEqual(findings, [])

    def test_finding_dataclass_fields(self):
        """Verify Finding fields and to_dict() returns all expected keys."""
        f = Finding(
            id="ETH-001",
            title="Reentrancy",
            severity="CRITICAL",
            confidence=0.95,
            file="contracts/Vault.sol",
            line=45,
            code_snippet="msg.sender.call{value: amount}('')",
            description="Reentrancy vulnerability",
            recommendation="Use nonReentrant modifier",
            category="reentrancy",
            swc="SWC-107",
            tool="slither",
        )
        d = f.to_dict()
        expected_keys = {"id", "title", "severity", "confidence", "file", "line",
                         "code_snippet", "description", "recommendation", "category",
                         "swc", "tool"}
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["id"], "ETH-001")
        self.assertEqual(d["tool"], "slither")

    def test_scan_results_scoring_all_severities(self):
        """ScanResults score calculation with mixed severities."""
        results = ScanResults(
            project="TestProject",
            timestamp="2026-01-01T00:00:00",
            tools_used=["slither", "aderyn"],
        )
        # Add one of each severity
        for sev, cat in [("CRITICAL", "reentrancy"), ("HIGH", "access-control"),
                          ("MEDIUM", "logic"), ("LOW", "misc"), ("INFORMATIONAL", "info")]:
            results.add_finding(Finding(
                id="ETH-001", title=f"Test {sev}", severity=sev,
                confidence=0.80, file="test.sol", line=1,
                code_snippet="", description="", recommendation="",
                category=cat,
            ))
        results.calculate_score()
        # 100 - 15 - 8 - 3 - 1 = 73
        self.assertEqual(results.security_score, 73)
        self.assertEqual(results.summary["total"], 5)
        self.assertEqual(results.summary["informational"], 1)

    def test_scan_results_to_dict(self):
        """ScanResults to_dict() returns correct structure."""
        results = ScanResults(
            project="TestProject",
            timestamp="2026-01-01T00:00:00",
            tools_used=["patterns"],
        )
        results.add_finding(Finding(
            id="ETH-071", title="Floating Pragma", severity="LOW",
            confidence=0.95, file="test.sol", line=1,
            code_snippet="pragma solidity ^0.8.0;", description="Floating",
            recommendation="Lock pragma", category="miscellaneous",
        ))
        results.calculate_score()
        d = results.to_dict()
        self.assertIn("project", d)
        self.assertIn("findings", d)
        self.assertIn("security_score", d)
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["id"], "ETH-071")


class TestReportGeneration(unittest.TestCase):
    """Integration tests for report generation."""

    def test_report_has_required_sections(self):
        """generate_report() produces markdown with all required sections."""
        data = {
            "project": "TestProtocol",
            "timestamp": "2026-01-15T12:00:00",
            "tools_used": ["slither", "patterns"],
            "findings": [{
                "id": "ETH-019",
                "title": "Delegatecall Usage",
                "severity": "CRITICAL",
                "confidence": 0.75,
                "file": "contracts/Proxy.sol",
                "line": 10,
                "code_snippet": "impl.delegatecall(msg.data)",
                "description": "Delegatecall to user-supplied address",
                "recommendation": "Only delegatecall to trusted contracts",
                "category": "external-calls",
                "swc": "SWC-112",
                "tool": "pattern-scanner",
            }],
            "summary": {
                "critical": 1, "high": 0, "medium": 0,
                "low": 0, "informational": 0, "total": 1,
            },
            "security_score": 85,
        }
        report = generate_report(data, project="TestProtocol")
        self.assertIn("Security Audit Report", report)
        self.assertIn("TestProtocol", report)
        self.assertIn("Executive Summary", report)
        self.assertIn("Scope & Methodology", report)
        self.assertIn("Findings Overview", report)
        self.assertIn("Detailed Findings", report)
        self.assertIn("Recommendations", report)
        self.assertIn("Appendix", report)
        self.assertIn("ETH-019", report)
        self.assertIn("85/100", report)


class TestFindingMerger(unittest.TestCase):
    """Tests for the finding_merger module."""

    def setUp(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from finding_merger import (
            merge_findings, filter_low_confidence, apply_context_filters,
        )
        self.merge_findings = merge_findings
        self.filter_low_confidence = filter_low_confidence
        self.apply_context_filters = apply_context_filters

    def test_finding_deduplication(self):
        """merge_findings deduplicates overlapping tool findings."""
        f1 = Finding(
            id="ETH-001", title="Reentrancy", severity="CRITICAL",
            confidence=0.80, file="Vault.sol", line=10,
            code_snippet="call{value:", description="Pattern scanner found reentrancy",
            recommendation="Fix", category="reentrancy", tool="pattern-scanner",
        )
        f2 = Finding(
            id="ETH-001", title="Reentrancy", severity="CRITICAL",
            confidence=0.85, file="Vault.sol", line=10,
            code_snippet="call{value:", description="Slither found reentrancy via detector",
            recommendation="Fix", category="reentrancy", tool="slither",
        )
        merged = self.merge_findings([[f1], [f2]])
        # Should deduplicate to 1 finding
        self.assertEqual(len(merged), 1)

    def test_confidence_boosting_two_tools(self):
        """Multi-tool agreement boosts confidence by 10%."""
        f1 = Finding(
            id="ETH-007", title="tx.origin", severity="CRITICAL",
            confidence=0.80, file="Auth.sol", line=5,
            code_snippet="tx.origin", description="Short desc",
            recommendation="Fix", category="access-control", tool="pattern-scanner",
        )
        f2 = Finding(
            id="ETH-007", title="tx.origin", severity="CRITICAL",
            confidence=0.85, file="Auth.sol", line=5,
            code_snippet="tx.origin", description="Slither found tx.origin authentication issue",
            recommendation="Fix", category="access-control", tool="slither",
        )
        merged = self.merge_findings([[f1], [f2]])
        self.assertEqual(len(merged), 1)
        # Longest description is f2 (0.85), boosted by 10% = 0.95
        self.assertGreaterEqual(merged[0].confidence, 0.90)

    def test_confidence_boosting_three_tools(self):
        """Three tools agreeing caps confidence at 0.95."""
        findings_lists = []
        for tool in ["pattern-scanner", "slither", "aderyn"]:
            findings_lists.append([Finding(
                id="ETH-071", title="Floating Pragma", severity="LOW",
                confidence=0.80, file="Test.sol", line=1,
                code_snippet="pragma solidity ^0.8.0;",
                description=f"{tool} found floating pragma" + ("!" * len(tool)),
                recommendation="Lock pragma", category="miscellaneous", tool=tool,
            )])
        merged = self.merge_findings(findings_lists)
        self.assertEqual(len(merged), 1)
        self.assertAlmostEqual(merged[0].confidence, 0.95)

    def test_low_confidence_filter(self):
        """filter_low_confidence removes findings below threshold."""
        findings = [
            Finding(id="ETH-001", title="A", severity="CRITICAL",
                    confidence=0.90, file="a.sol", line=1,
                    code_snippet="", description="", recommendation="",
                    category="reentrancy"),
            Finding(id="ETH-071", title="B", severity="LOW",
                    confidence=0.50, file="b.sol", line=1,
                    code_snippet="", description="", recommendation="",
                    category="misc"),
            Finding(id="ETH-013", title="C", severity="HIGH",
                    confidence=0.69, file="c.sol", line=1,
                    code_snippet="", description="", recommendation="",
                    category="arithmetic"),
        ]
        filtered = self.filter_low_confidence(findings, threshold=0.7)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "ETH-001")

    def test_context_filter_reentrancy_guard(self):
        """Context filter removes reentrancy FP when nonReentrant is present."""
        source_code = """
pragma solidity 0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    mapping(address => uint) public balances;
    function withdraw(uint amount) external nonReentrant {
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent);
        balances[msg.sender] -= amount;
    }
}
"""
        finding = Finding(
            id="ETH-001", title="Reentrancy", severity="CRITICAL",
            confidence=0.85, file="Safe.sol", line=7,
            code_snippet="msg.sender.call{value: amount}",
            description="CEI violation", recommendation="Add guard",
            category="reentrancy", tool="pattern-scanner",
        )
        filtered = self.apply_context_filters([finding], source_code)
        self.assertEqual(len(filtered), 0, "Should filter out reentrancy when nonReentrant is present")

    def test_context_filter_keeps_real_vuln(self):
        """Context filter keeps findings without compensating controls."""
        source_code = """
pragma solidity 0.8.20;
contract Unsafe {
    mapping(address => uint) public balances;
    function withdraw(uint amount) external {
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent);
        balances[msg.sender] -= amount;
    }
}
"""
        finding = Finding(
            id="ETH-001", title="Reentrancy", severity="CRITICAL",
            confidence=0.85, file="Unsafe.sol", line=5,
            code_snippet="msg.sender.call{value: amount}",
            description="CEI violation", recommendation="Add guard",
            category="reentrancy", tool="pattern-scanner",
        )
        filtered = self.apply_context_filters([finding], source_code)
        self.assertEqual(len(filtered), 1, "Should keep reentrancy finding without guard")


if __name__ == "__main__":
    unittest.main()
