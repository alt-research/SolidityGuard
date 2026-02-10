#!/usr/bin/env python3
"""
SolidityGuard Web API Integration Tests

Tests for the FastAPI backend using TestClient.

Usage:
    python3 -m pytest test_api.py -v
    python3 test_api.py
"""

import sys
import unittest
from pathlib import Path

# Ensure the backend package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from solidityguard_api.main import app


class TestHealthEndpoint(unittest.TestCase):
    """Tests for /api/health."""

    def setUp(self):
        self.client = TestClient(app)

    def test_health_returns_200(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["version"], "1.0.1")
        self.assertIn("timestamp", data)


class TestPatternsEndpoint(unittest.TestCase):
    """Tests for /api/patterns."""

    def setUp(self):
        self.client = TestClient(app)

    def test_list_all_patterns(self):
        response = self.client.get("/api/patterns")
        self.assertEqual(response.status_code, 200)
        patterns = response.json()
        self.assertEqual(len(patterns), 104)

    def test_patterns_have_required_fields(self):
        response = self.client.get("/api/patterns")
        patterns = response.json()
        for p in patterns:
            self.assertIn("id", p)
            self.assertIn("title", p)
            self.assertIn("severity", p)
            self.assertIn("category", p)
            self.assertIn("description", p)

    def test_filter_by_category(self):
        response = self.client.get("/api/patterns?category=reentrancy")
        self.assertEqual(response.status_code, 200)
        patterns = response.json()
        self.assertTrue(len(patterns) >= 1)
        for p in patterns:
            self.assertEqual(p["category"], "reentrancy")

    def test_filter_by_severity(self):
        response = self.client.get("/api/patterns?severity=CRITICAL")
        self.assertEqual(response.status_code, 200)
        patterns = response.json()
        self.assertTrue(len(patterns) >= 1)
        for p in patterns:
            self.assertEqual(p["severity"], "CRITICAL")

    def test_get_specific_pattern(self):
        response = self.client.get("/api/patterns/ETH-001")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["id"], "ETH-001")
        self.assertEqual(data["severity"], "CRITICAL")
        self.assertEqual(data["category"], "reentrancy")

    def test_get_nonexistent_pattern(self):
        response = self.client.get("/api/patterns/ETH-999")
        self.assertEqual(response.status_code, 404)


class TestToolsEndpoint(unittest.TestCase):
    """Tests for /api/tools."""

    def setUp(self):
        self.client = TestClient(app)

    def test_list_tools(self):
        response = self.client.get("/api/tools")
        self.assertEqual(response.status_code, 200)
        tools = response.json()
        self.assertTrue(len(tools) >= 1)
        tool_names = [t["name"] for t in tools]
        self.assertIn("slither", tool_names)
        self.assertIn("mythril", tool_names)

    def test_tools_have_required_fields(self):
        response = self.client.get("/api/tools")
        tools = response.json()
        for t in tools:
            self.assertIn("name", t)
            self.assertIn("available", t)


class TestAuditEndpoint(unittest.TestCase):
    """Tests for /api/audit."""

    def setUp(self):
        self.client = TestClient(app)

    def test_audit_missing_input(self):
        response = self.client.post("/api/audit")
        # Auth check (401) runs before input validation (400)
        self.assertIn(response.status_code, (400, 401))

    def test_audit_nonexistent_path(self):
        response = self.client.post("/api/audit/json", json={
            "path": "/nonexistent/path",
        })
        self.assertEqual(response.status_code, 400)

    def test_get_nonexistent_audit(self):
        response = self.client.get("/api/audit/nonexistent-id")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
