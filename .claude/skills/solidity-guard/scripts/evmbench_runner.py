#!/usr/bin/env python3
"""
EVMBench Runner for SolidityGuard
==================================

Runs SolidityGuard agent against EVMBench tasks using the nanoeval framework.

Prerequisites:
  - EVMBench repo cloned: git clone https://github.com/openai/frontier-evals.git
  - Python deps: pip install -e frontier-evals/project/evmbench
  - Docker running (for Alcatraz containers)
  - ANTHROPIC_API_KEY set

Usage:
  # Run all detect tasks
  python evmbench_runner.py --mode detect

  # Run all patch tasks
  python evmbench_runner.py --mode patch

  # Run all exploit tasks
  python evmbench_runner.py --mode exploit

  # Run a single audit
  python evmbench_runner.py --mode detect --audit 2024-04-noya

  # Run with the baseline Claude agent (for comparison)
  python evmbench_runner.py --mode detect --agent claude-default

  # Run with hints
  python evmbench_runner.py --mode detect --hints low

  # Dry run (just list tasks, don't execute)
  python evmbench_runner.py --mode detect --dry-run
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_evmbench_dir() -> Path:
    """Locate the EVMBench project directory."""
    candidates = [
        Path.home() / "github" / "frontier-evals" / "project" / "evmbench",
        Path.home() / "frontier-evals" / "project" / "evmbench",
        Path(__file__).resolve().parent.parent.parent.parent.parent / "frontier-evals" / "project" / "evmbench",
    ]
    for c in candidates:
        if c.exists() and (c / "evmbench").exists():
            return c
    return None


def find_solidityguard_dir() -> Path:
    """Locate the SolidityGuard project directory."""
    candidates = [
        Path.home() / "github" / "solidity-audit",
        Path(__file__).resolve().parent.parent.parent.parent.parent,
    ]
    for c in candidates:
        if c.exists() and (c / "CLAUDE.md").exists():
            return c
    return None


def ensure_agent_installed(evmbench_dir: Path, sg_dir: Path) -> None:
    """Copy SolidityGuard agent files into EVMBench agents directory."""
    agent_dir = evmbench_dir / "evmbench" / "agents" / "solidityguard"
    instructions_dir = agent_dir / "instructions"
    instructions_dir.mkdir(parents=True, exist_ok=True)

    scripts_dir = sg_dir / ".claude" / "skills" / "solidity-guard" / "scripts"

    # Copy files
    files_to_copy = [
        (scripts_dir / "evmbench_agent" / "config.yaml", agent_dir / "config.yaml"),
        (scripts_dir / "evmbench_bootstrap.sh", agent_dir / "evmbench_bootstrap.sh"),
        (scripts_dir / "solidity_guard.py", agent_dir / "solidity_guard.py"),
        (scripts_dir / "evmbench_instructions" / "detect.md", instructions_dir / "DETECT.md"),
        (scripts_dir / "evmbench_instructions" / "patch.md", instructions_dir / "PATCH.md"),
        (scripts_dir / "evmbench_instructions" / "exploit.md", instructions_dir / "EXPLOIT.md"),
    ]

    for src, dst in files_to_copy:
        if src.exists():
            shutil.copy2(src, dst)
        else:
            print(f"  [WARN] {src} not found, skipping")

    # start.sh needs to be executable
    start_sh = agent_dir / "start.sh"
    if start_sh.exists():
        start_sh.chmod(0o755)

    print(f"[OK] SolidityGuard agent installed at {agent_dir}")


def get_split_file(mode: str) -> str:
    """Get the EVMBench split file name for a mode."""
    return {
        "detect": "detect-tasks",
        "patch": "patch-tasks",
        "exploit": "exploit-tasks",
    }[mode]


def list_tasks(evmbench_dir: Path, mode: str, audit: str = None) -> list[str]:
    """List audit IDs for a given mode."""
    if audit:
        return [audit]
    split_file = evmbench_dir / "splits" / f"{get_split_file(mode)}.txt"
    if not split_file.exists():
        print(f"[ERROR] Split file not found: {split_file}")
        return []
    return [line.strip() for line in split_file.read_text().splitlines() if line.strip()]


def run_evmbench(
    evmbench_dir: Path,
    mode: str,
    agent_id: str = "solidityguard-default",
    audit: str = None,
    hints: str = "none",
    concurrency: int = 3,
    timeout: int = 36000,
    detect_iterations: int = 1,
    dry_run: bool = False,
) -> dict:
    """Run EVMBench evaluation."""
    tasks = list_tasks(evmbench_dir, mode, audit)
    print(f"\n{'='*60}")
    print("EVMBench Runner — SolidityGuard")
    print(f"{'='*60}")
    print(f"Mode: {mode}")
    print(f"Agent: {agent_id}")
    print(f"Tasks: {len(tasks)}")
    print(f"Hints: {hints}")
    print(f"Concurrency: {concurrency}")
    print(f"Timeout: {timeout}s")
    if detect_iterations > 1:
        print(f"Detect iterations: {detect_iterations}")
    print(f"{'='*60}\n")

    for i, task_id in enumerate(tasks, 1):
        print(f"  [{i:2d}/{len(tasks)}] {task_id}")
    print()

    if dry_run:
        print("[DRY RUN] Would run the above tasks. Exiting.")
        return {"mode": mode, "tasks": tasks, "dry_run": True}

    # Build the nanoeval command
    cmd = [
        sys.executable, "-m", "evmbench.nano.entrypoint",
        f"--evmbench.mode={mode}",
        f"--evmbench.solver.agent_id={agent_id}",
        f"--evmbench.solver.timeout={timeout}",
        f"--evmbench.hint_level={hints}",
        f"--runner.concurrency={concurrency}",
    ]

    if audit:
        cmd.append(f"--evmbench.audit={audit}")
    else:
        cmd.append(f"--evmbench.audit_split={get_split_file(mode)}")

    if detect_iterations > 1:
        cmd.append(f"--evmbench.solver.detect_iterations={detect_iterations}")

    print(f"[RUN] {' '.join(cmd)}\n")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(evmbench_dir) + ":" + env.get("PYTHONPATH", "")

    result = subprocess.run(
        cmd,
        cwd=str(evmbench_dir),
        env=env,
    )

    return {"mode": mode, "agent": agent_id, "exit_code": result.returncode}


def main():
    parser = argparse.ArgumentParser(
        description="EVMBench Runner for SolidityGuard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--mode", choices=["detect", "patch", "exploit"], required=True,
                        help="EVMBench evaluation mode")
    parser.add_argument("--agent", default="solidityguard-default",
                        help="Agent ID (default: solidityguard-default)")
    parser.add_argument("--audit", default=None,
                        help="Run a single audit by ID (e.g., 2024-04-noya)")
    parser.add_argument("--hints", default="none", choices=["none", "low", "med", "high", "max"],
                        help="Hint level (default: none)")
    parser.add_argument("--concurrency", type=int, default=3,
                        help="Number of concurrent tasks (default: 3)")
    parser.add_argument("--timeout", type=int, default=36000,
                        help="Agent timeout in seconds (default: 36000)")
    parser.add_argument("--detect-iterations", type=int, default=1,
                        help="Number of detect iterations (default: 1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="List tasks without running them")
    parser.add_argument("--install", action="store_true",
                        help="Install/update SolidityGuard agent files in EVMBench repo")
    parser.add_argument("--evmbench-dir", default=None,
                        help="Path to EVMBench project directory")

    args = parser.parse_args()

    # Find directories
    if args.evmbench_dir:
        evmbench_dir = Path(args.evmbench_dir)
    else:
        evmbench_dir = find_evmbench_dir()
    if not evmbench_dir or not evmbench_dir.exists():
        print("[ERROR] EVMBench directory not found. Clone it first:")
        print("  git clone https://github.com/openai/frontier-evals.git")
        sys.exit(1)

    sg_dir = find_solidityguard_dir()

    if args.install or not (evmbench_dir / "evmbench" / "agents" / "solidityguard" / "config.yaml").exists():
        if not sg_dir:
            print("[ERROR] SolidityGuard directory not found")
            sys.exit(1)
        ensure_agent_installed(evmbench_dir, sg_dir)
        if args.install:
            print("Agent files installed. Run again without --install to execute.")
            return

    # Check prerequisites
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[ERROR] ANTHROPIC_API_KEY not set")
        sys.exit(1)

    result = run_evmbench(
        evmbench_dir=evmbench_dir,
        mode=args.mode,
        agent_id=args.agent,
        audit=args.audit,
        hints=args.hints,
        concurrency=args.concurrency,
        timeout=args.timeout,
        detect_iterations=args.detect_iterations,
        dry_run=args.dry_run,
    )

    if result.get("exit_code", 0) != 0:
        sys.exit(result["exit_code"])


if __name__ == "__main__":
    main()
