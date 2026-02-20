"""Rich terminal UI components for SolidityGuard CLI."""

import shutil
import subprocess
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFORMATIONAL": "dim",
    "INFO": "dim",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def print_banner():
    """Print the SolidityGuard banner."""
    banner = Text()
    banner.append("SolidityGuard", style="bold green")
    from solidityguard import __version__
    banner.append(f" v{__version__}", style="dim")
    banner.append(" -- Smart Contract Security Audit", style="")
    console.print(Panel(banner, border_style="green"))


def print_target_info(target: str, file_count: int, line_count: int):
    """Print target project info."""
    console.print(f"  Target: [bold]{target}[/bold] ({file_count} files, {line_count:,} lines)")


def print_tool_status(tools: dict[str, bool]):
    """Print tool availability status."""
    parts = []
    for name, available in tools.items():
        if available:
            parts.append(f"[green]{name}[/green] [green]OK[/green]")
        else:
            parts.append(f"[red]{name}[/red] [red]--[/red]")
    console.print(f"  Tools:  {' | '.join(parts)}")


def print_scan_progress(phase: int, total: int, name: str):
    """Print a scan phase header."""
    console.print()
    console.rule(f"Phase {phase}/{total}  {name}", style="cyan")


def print_severity_chart(summary: dict):
    """Print a horizontal bar chart of severity distribution."""
    console.print()
    console.rule("Severity Distribution", style="cyan")
    console.print()

    max_count = max(summary.get("critical", 0), summary.get("high", 0),
                    summary.get("medium", 0), summary.get("low", 0),
                    summary.get("informational", 0), 1)

    terminal_width = shutil.get_terminal_size().columns
    bar_max = min(40, terminal_width - 25)

    for sev, key in [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"),
                     ("LOW", "low"), ("INFO", "informational")]:
        count = summary.get(key, 0)
        bar_len = int((count / max_count) * bar_max) if max_count > 0 else 0
        bar = "#" * bar_len
        color = SEVERITY_COLORS.get(sev, "white")
        label = f"  {sev:<10} {count:>2}  "
        console.print(f"{label}[{color}]{bar}[/{color}]")


def print_findings(findings: list, max_display: int = 20):
    """Print findings as Rich panels grouped by severity."""
    if not findings:
        console.print("\n  [green]No findings.[/green]")
        return

    console.print()
    console.rule("Findings", style="cyan")

    # Sort by severity
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    sorted_findings = sorted(findings, key=lambda f: (sev_rank.get(f.severity, 5), -f.confidence))

    displayed = 0
    for finding in sorted_findings:
        if displayed >= max_display:
            remaining = len(sorted_findings) - max_display
            console.print(f"\n  [dim]... and {remaining} more findings[/dim]")
            break

        color = SEVERITY_COLORS.get(finding.severity, "white")
        tool_label = f"  [{finding.tool}]" if hasattr(finding, "tool") and finding.tool else ""
        header = f"{finding.severity}  {finding.id}  {finding.title}{tool_label}"

        content = []
        if finding.file:
            loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
            confidence_str = f"Confidence: {finding.confidence:.0%}"
            tool_str = f"  |  Tool: {finding.tool}" if hasattr(finding, "tool") and finding.tool else ""
            content.append(f"Location: {loc}  |  {confidence_str}{tool_str}")
        if finding.code_snippet:
            content.append(f"\n  {finding.code_snippet}")
        if finding.description:
            content.append(f"\n{finding.description}")
        if finding.recommendation:
            content.append(f"\n[dim]Fix: {finding.recommendation}[/dim]")

        console.print(Panel(
            "\n".join(content),
            title=f"[{color}]{header}[/{color}]",
            border_style=color.replace("bold ", ""),
            padding=(0, 1),
        ))
        displayed += 1


def print_score(score: int, total_findings: int, file_count: int):
    """Print the final security score banner."""
    console.print()
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "dark_orange"
    else:
        color = "red"

    console.print(Panel(
        f"[{color} bold]Score: {score}/100[/{color} bold]  |  "
        f"{total_findings} findings  |  {file_count} files scanned",
        border_style=color,
    ))


def print_patterns_table(patterns: list, category_filter: Optional[str] = None):
    """Print all vulnerability patterns as a Rich table."""
    table = Table(title="SolidityGuard Vulnerability Patterns (104)", show_lines=False)
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Pattern", min_width=30)
    table.add_column("Severity", width=10)
    table.add_column("SWC", width=8)
    table.add_column("Category", width=18)

    for pid, name, severity, swc, category in patterns:
        if category_filter and category.lower() != category_filter.lower():
            continue
        color = SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            pid,
            name,
            f"[{color}]{severity}[/{color}]",
            swc or "--",
            category,
        )

    console.print(table)


def print_tools_table(tools_status: dict):
    """Print tool availability as a Rich table."""
    table = Table(title="Security Tools", show_lines=False)
    table.add_column("Tool", style="cyan", width=12)
    table.add_column("Status", width=12)
    table.add_column("Version", width=20)
    table.add_column("Description", min_width=30)
    table.add_column("Install", min_width=25)

    for name, info in tools_status.items():
        if info["available"]:
            status = "[green]Installed[/green]"
            version = info.get("version", "")
        else:
            status = "[red]Missing[/red]"
            version = "--"

        table.add_row(
            info["display_name"],
            status,
            version,
            info["description"],
            info["install"],
        )

    console.print(table)


def check_tool(command: str, args: list) -> tuple[bool, str]:
    """Check if a tool is installed and return (available, version_string)."""
    try:
        result = subprocess.run(
            [command] + args,
            capture_output=True, text=True, timeout=10,
        )
        version = result.stdout.strip().split("\n")[0] if result.stdout.strip() else ""
        if not version and result.stderr.strip():
            version = result.stderr.strip().split("\n")[0]
        return True, version
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, ""
