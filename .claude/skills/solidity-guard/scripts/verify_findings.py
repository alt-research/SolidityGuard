#!/usr/bin/env python3
"""
SolidityGuard Finding Verifier

Generates verification prompts with code context for each finding.
Use to reduce false positives by providing focused verification tasks.

Usage:
    python3 verify_findings.py results.json
    python3 verify_findings.py results.json --severity critical,high
"""

import argparse
import json
import os
import sys


def generate_verification_prompts(data: dict, severity_filter: list = None) -> list:
    """Generate verification prompts for findings."""
    findings = data.get("findings", [])
    prompts = []

    if severity_filter:
        findings = [f for f in findings if f.get("severity", "").upper() in severity_filter]

    for f in findings:
        file_path = f.get("file", "")
        line = f.get("line", 0)
        finding_id = f.get("id", "unknown")
        title = f.get("title", "Unknown Finding")
        severity = f.get("severity", "UNKNOWN")
        description = f.get("description", "")

        prompt = f"""### Verify {finding_id}: {title} ({severity})

**Location**: `{file_path}:{line}`
**Tool**: {f.get("tool", "unknown")}
**Confidence**: {f.get("confidence", 0):.0%}

**Task**: Read the code at `{file_path}` around line {line} and determine:

1. **Is this a TRUE POSITIVE or FALSE POSITIVE?**
   - Read the actual code context (5-10 lines before and after)
   - Check if the vulnerability exists as described
   - Look for mitigations elsewhere (inherited contracts, libraries, modifiers)

2. **If TRUE POSITIVE:**
   - Describe the exact attack scenario
   - Estimate the impact (fund loss, DoS, etc.)
   - Provide the fixed code

3. **If FALSE POSITIVE:**
   - Explain why the tool flagged it
   - Identify the compensating control

**Finding Description**: {description}

---
"""
        prompts.append({
            "finding_id": finding_id,
            "severity": severity,
            "file": file_path,
            "line": line,
            "prompt": prompt,
        })

    return prompts


def main():
    parser = argparse.ArgumentParser(description="SolidityGuard Finding Verifier")
    parser.add_argument("input", help="Path to scan results JSON file")
    parser.add_argument("--severity", default="critical,high",
                        help="Comma-separated severities to verify")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)

    severity_filter = [s.strip().upper() for s in args.severity.split(",")]
    prompts = generate_verification_prompts(data, severity_filter)

    print(f"Generated {len(prompts)} verification prompts")
    print(f"Severities: {', '.join(severity_filter)}")
    print("=" * 60)

    for p in prompts:
        print(p["prompt"])


if __name__ == "__main__":
    main()
