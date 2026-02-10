"""Click command definitions for SolidityGuard CLI."""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import click

from solidityguard import __version__
from solidityguard.config import (
    ALL_PATTERNS,
    PATTERN_CATEGORIES,
    TOOLS,
    get_benchmark_path,
    get_scripts_dir,
)
from solidityguard.scanner import (
    calculate_score,
    count_solidity_files,
    deduplicate_findings,
    run_aderyn,
    run_slither,
    scan,
)
from solidityguard.ui import (
    check_tool,
    console,
    print_banner,
    print_findings,
    print_patterns_table,
    print_scan_progress,
    print_score,
    print_severity_chart,
    print_target_info,
    print_tool_status,
    print_tools_table,
)


@click.group()
def cli():
    """SolidityGuard -- AI-powered Solidity smart contract security audit."""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, help="Run deep audit with multi-agent analysis.")
@click.option("--quick", is_flag=True, help="Run quick scan only (pattern scanner).")
@click.option("--output", "-o", type=click.Path(), help="Save findings to JSON file.")
@click.option("--max-findings", default=50, help="Maximum findings to display.", show_default=True)
def audit(target, deep, quick, output, max_findings):
    """Run a full security audit on Solidity contracts.

    TARGET is the path to a contracts directory or project root.
    """
    print_banner()

    # Target info
    file_count, line_count = count_solidity_files(target)
    print_target_info(target, file_count, line_count)

    if file_count == 0:
        console.print("\n  [yellow]No .sol files found in target directory.[/yellow]")
        return

    # Check tools
    tool_avail = {}
    for key in ["slither", "aderyn", "mythril", "foundry"]:
        info = TOOLS[key]
        available, _ = check_tool(info["command"], info["check_args"])
        tool_avail[info["name"]] = available
    tool_avail["Pattern Scanner"] = True
    print_tool_status(tool_avail)

    # Determine phases
    slither_avail = not quick and tool_avail.get("Slither", False)
    aderyn_avail = not quick and tool_avail.get("Aderyn", False)
    tool_phases = sum([slither_avail, aderyn_avail])
    # Phases: pattern scan + (slither?) + (aderyn?) + verification (if not quick)
    total_phases = 1 + tool_phases + (1 if not quick else 0)
    phase = 0

    # Phase: Pattern scan
    phase += 1
    print_scan_progress(phase, total_phases, "Pattern Scanner (104 patterns)")
    findings = scan(target)
    console.print(f"  Found {len(findings)} issues")

    # Phase: Slither (if available and not quick)
    if slither_avail:
        phase += 1
        print_scan_progress(phase, total_phases, "Slither Static Analysis")
        try:
            slither_findings = run_slither(target)
            findings.extend(slither_findings)
            console.print(f"  Slither found {len(slither_findings)} issues")
        except Exception:
            console.print("  [yellow]Slither analysis skipped[/yellow]")

    # Phase: Aderyn (if available and not quick)
    if aderyn_avail:
        phase += 1
        print_scan_progress(phase, total_phases, "Aderyn Static Analysis")
        try:
            aderyn_findings = run_aderyn(target)
            findings.extend(aderyn_findings)
            console.print(f"  Aderyn found {len(aderyn_findings)} issues")
        except Exception:
            console.print("  [yellow]Aderyn analysis skipped[/yellow]")

    # Phase: Verification + deduplication
    if not quick:
        phase += 1
        print_scan_progress(phase, total_phases, "Finding Verification & Deduplication")
        before = len(findings)
        findings = [f for f in findings if f.confidence >= 0.5]
        findings = deduplicate_findings(findings)
        console.print(f"  Verified {len(findings)}/{before} findings (confidence >= 50%, deduplicated)")

    # Results
    summary = calculate_score(findings)
    print_severity_chart(summary)
    print_findings(findings, max_display=max_findings)
    print_score(summary["score"], summary["total"], file_count)

    # Save to file
    if output:
        # Collect which tools actually contributed findings
        tools_used = sorted(set(f.tool for f in findings))
        output_data = {
            "project": str(Path(target).resolve()),
            "timestamp": datetime.now().isoformat(),
            "tools_used": tools_used,
            "summary": summary,
            "security_score": summary["score"],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "file": f.file,
                    "line": f.line,
                    "code_snippet": f.code_snippet,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "category": f.category,
                    "swc": f.swc,
                    "tool": f.tool,
                }
                for f in findings
            ],
        }
        Path(output).write_text(json.dumps(output_data, indent=2))
        console.print(f"\n  Results saved to [cyan]{output}[/cyan]")


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--category", "-c", help="Filter by category (e.g. reentrancy, defi, oracle).")
@click.option("--pattern", "-p", help="Filter by specific pattern ID (e.g. ETH-001).")
@click.option("--output", "-o", type=click.Path(), help="Save findings to JSON file.")
def scan_cmd(target, category, pattern, output):
    """Scan contracts for specific vulnerability patterns.

    TARGET is the path to a contracts directory.
    """
    print_banner()

    file_count, line_count = count_solidity_files(target)
    print_target_info(target, file_count, line_count)

    if file_count == 0:
        console.print("\n  [yellow]No .sol files found.[/yellow]")
        return

    filter_desc = "all patterns"
    if pattern:
        filter_desc = f"pattern {pattern}"
    elif category:
        filter_desc = f"category: {category}"
    console.print(f"  Filter: {filter_desc}")

    findings = scan(target, category=category, pattern=pattern)
    summary = calculate_score(findings)

    print_severity_chart(summary)
    print_findings(findings)
    print_score(summary["score"], summary["total"], file_count)

    if output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "filter": {"category": category, "pattern": pattern},
            "findings": [
                {
                    "id": f.id, "title": f.title, "severity": f.severity,
                    "confidence": f.confidence, "file": f.file, "line": f.line,
                    "description": f.description,
                }
                for f in findings
            ],
        }
        Path(output).write_text(json.dumps(output_data, indent=2))
        console.print(f"\n  Results saved to [cyan]{output}[/cyan]")


# Register 'scan' as the command name (scan_cmd is the function name to avoid
# shadowing the scanner.scan import)
scan_cmd.name = "scan"


@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", type=click.Choice(["markdown", "pdf"]),
              default="markdown", help="Output format.")
@click.option("--output", "-o", type=click.Path(), help="Output file path.")
@click.option("--project", default="", help="Project name for report header.")
@click.option("--client", default="", help="Client name for report header.")
def report(findings_file, fmt, output, project, client):
    """Generate a professional audit report from findings JSON.

    FINDINGS_FILE is a JSON file produced by the audit or scan command.
    """
    print_banner()

    data = json.loads(Path(findings_file).read_text())
    findings = data.get("findings", [])

    if not findings:
        console.print("  [yellow]No findings in input file.[/yellow]")
        return

    console.print(f"  Input: {findings_file} ({len(findings)} findings)")

    # Use the professional report generator
    from solidityguard.scanner import _ensure_scanner_importable
    _ensure_scanner_importable()
    from report_generator import generate_report

    md_content = generate_report(data, project=project, client=client)

    md_path = output or "audit-report.md"
    if fmt == "pdf" and md_path.endswith(".pdf"):
        md_path = md_path.replace(".pdf", ".md")

    Path(md_path).write_text(md_content)
    console.print(f"\n  Report saved to [cyan]{md_path}[/cyan]")

    if fmt == "pdf":
        pdf_path = md_path.replace(".md", ".pdf")
        try:
            subprocess.run(
                ["pandoc", md_path, "-o", pdf_path, "--toc"],
                capture_output=True, check=True, timeout=60,
            )
            console.print(f"  PDF saved to [cyan]{pdf_path}[/cyan]")
        except FileNotFoundError:
            console.print("  [yellow]pandoc not installed. Install for PDF generation.[/yellow]")
        except subprocess.CalledProcessError as e:
            console.print(f"  [yellow]PDF generation failed: {e}[/yellow]")
        except subprocess.TimeoutExpired:
            console.print("  [yellow]PDF generation timed out[/yellow]")


@cli.command()
@click.option("--paradigm", is_flag=True, help="Run Paradigm CTF benchmark only.")
@click.option("--all", "run_all", is_flag=True, help="Run all benchmarks (DeFiVulnLabs + Paradigm CTF).")
def benchmark(paradigm, run_all):
    """Run CTF benchmarks to validate scanner detection rates."""
    print_banner()
    console.print("  Running CTF Benchmark...")
    console.print()

    benchmark_script = str(get_benchmark_path())
    if not Path(benchmark_script).exists():
        console.print(f"  [red]Benchmark script not found: {benchmark_script}[/red]")
        return

    cmd = [sys.executable, benchmark_script]
    if run_all:
        cmd.append("--all")
    elif paradigm:
        cmd.append("--paradigm")

    try:
        result = subprocess.run(
            cmd, capture_output=False, text=True, timeout=600,
        )
        if result.returncode != 0:
            console.print(f"\n  [red]Benchmark exited with code {result.returncode}[/red]")
    except subprocess.TimeoutExpired:
        console.print("\n  [red]Benchmark timed out after 600s[/red]")
    except FileNotFoundError:
        console.print(f"\n  [red]Python interpreter not found[/red]")


@cli.command()
@click.option("--category", "-c", help="Filter by category name.")
def patterns(category):
    """List all 104 vulnerability patterns."""
    print_banner()
    print_patterns_table(ALL_PATTERNS, category_filter=category)

    if not category:
        console.print(f"\n  [dim]104 patterns across {len(PATTERN_CATEGORIES)} categories[/dim]")
        console.print("  [dim]Filter by category: solidityguard patterns --category reentrancy[/dim]")


@cli.command()
def tools():
    """Check availability of security analysis tools."""
    print_banner()

    tools_status = {}
    for key, info in TOOLS.items():
        available, version = check_tool(info["command"], info["check_args"])
        tools_status[key] = {
            "display_name": info["name"],
            "available": available,
            "version": version,
            "description": info["description"],
            "install": info["install"],
        }

    # Always show pattern scanner
    tools_status["pattern-scanner"] = {
        "display_name": "Pattern Scanner",
        "available": True,
        "version": "Built-in (50+ detectors, 104 patterns)",
        "description": "Regex-based pattern detection engine",
        "install": "Built-in",
    }

    print_tools_table(tools_status)

    installed = sum(1 for t in tools_status.values() if t["available"])
    total = len(tools_status)
    console.print(f"\n  {installed}/{total} tools available")


@cli.command(name="generate-fuzz")
@click.argument("findings_file", type=click.Path(exists=True))
@click.argument("contracts_path", type=click.Path(exists=True))
@click.option("--output-dir", "-o", type=click.Path(), default="test",
              help="Output directory for generated tests.", show_default=True)
@click.option("--foundry-only", is_flag=True, help="Only generate Foundry invariant tests.")
@click.option("--echidna-only", is_flag=True, help="Only generate Echidna property tests.")
def generate_fuzz(findings_file, contracts_path, output_dir, foundry_only, echidna_only):
    """Generate Foundry invariant tests and Echidna property tests from findings.

    FINDINGS_FILE is a JSON file produced by the audit or scan command.
    CONTRACTS_PATH is the root directory of the Solidity contracts.
    """
    print_banner()

    data = json.loads(Path(findings_file).read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data

    if not findings:
        console.print("  [yellow]No findings in input file.[/yellow]")
        return

    console.print(f"  Input: {findings_file} ({len(findings)} findings)")
    console.print(f"  Contracts: {contracts_path}")

    # Import the generator
    import sys as _sys
    scripts_dir = str(get_scripts_dir())
    if scripts_dir not in _sys.path:
        _sys.path.insert(0, scripts_dir)
    from fuzz_generator import generate_from_json

    result = generate_from_json(findings, contracts_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not echidna_only and result["foundry_test"]:
        foundry_path = out / "SolidityGuard.invariant.t.sol"
        foundry_path.write_text(result["foundry_test"])
        console.print(f"\n  Foundry test: [cyan]{foundry_path}[/cyan]")

    if not foundry_only and result["echidna_test"]:
        echidna_dir = out / "echidna"
        echidna_dir.mkdir(parents=True, exist_ok=True)
        (echidna_dir / "SolidityGuardEchidna.sol").write_text(result["echidna_test"])
        (echidna_dir / "echidna.yaml").write_text(result["echidna_config"])
        console.print(f"  Echidna test: [cyan]{echidna_dir / 'SolidityGuardEchidna.sol'}[/cyan]")
        console.print(f"  Echidna config: [cyan]{echidna_dir / 'echidna.yaml'}[/cyan]")

    s = result["summary"]
    console.print(f"\n  Generated from {s['total_findings']} findings:")
    console.print(f"    Foundry tests/invariants: {s['foundry_tests_generated']}")
    console.print(f"    Echidna properties:       {s['echidna_properties_generated']}")

    console.print("\n  [bold]Run instructions:[/bold]")
    if not echidna_only:
        console.print("    Foundry:  [dim]forge test --match-contract SolidityGuardInvariantTest -vvvv[/dim]")
    if not foundry_only:
        console.print("    Echidna:  [dim]echidna . --contract SolidityGuardEchidnaTest --config test/echidna/echidna.yaml[/dim]")


@cli.command()
def version():
    """Show SolidityGuard version information."""
    print_banner()
    console.print(f"  Version:  {__version__}")
    console.print(f"  Patterns: 104 (ETH-001 to ETH-104)")
    console.print(f"  Detectors: 50+")
    console.print(f"  Benchmarks: DeFiVulnLabs 56/56 | Paradigm CTF 24/24")
