#!/usr/bin/env python3
"""
scripts/fresh_clone_test.py

Validates repository reproducibility from scratch:
1. Clones (or cleanly exports) the repository into a temporary directory
2. Creates an isolated Python virtual environment (.venv)
3. Installs packages in editable mode
4. Runs full pytest test suite
5. Runs adversarial safety evaluation benchmark (61 cases)
6. Starts the Aegis server in a background process and verifies GET /health
7. Prints a per-step PASS/FAIL report and exits non-zero on failure
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_command(cmd: list[str], cwd: Path, description: str, timeout: int = 120) -> tuple[bool, str]:
    print(f"[*] {description} ...")
    start = time.time()
    try:
        res = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.time() - start
        if res.returncode == 0:
            print(f"    [+] PASS ({elapsed:.1f}s)")
            return True, ""
        else:
            err_msg = res.stderr.strip() or res.stdout.strip()
            print(f"    [-] FAIL ({elapsed:.1f}s): Return code {res.returncode}")
            if err_msg:
                # Print first 5 lines of error
                lines = err_msg.splitlines()[:5]
                for l in lines:
                    print(f"        {l}")
            return False, err_msg
    except subprocess.TimeoutExpired:
        print(f"    [-] FAIL: Timed out after {timeout}s")
        return False, "Timeout expired"
    except Exception as e:
        print(f"    [-] FAIL: {e}")
        return False, str(e)


def is_git_ignored(file_path: Path, repo_root: Path) -> bool:
    try:
        rel = file_path.relative_to(repo_root).as_posix()
        res = subprocess.run(
            ["git", "check-ignore", "-q", rel],
            cwd=str(repo_root),
            capture_output=True,
        )
        return res.returncode == 0
    except Exception:
        return False


def clone_or_export_repo(source_root: Path, target_dir: Path) -> bool:
    """Clone if committed, or export non-ignored files if uncommitted."""
    # Check if git has commits
    has_commits = False
    try:
        res = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=str(source_root), capture_output=True)
        has_commits = (res.returncode == 0)
    except Exception:
        has_commits = False

    if has_commits:
        cmd = ["git", "clone", str(source_root), str(target_dir)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return True

    # Fallback export: copy all non-git-ignored files
    ignored_dir_names = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", ".idea", ".vscode", "logs"}
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in ignored_dir_names and not d.endswith(".egg-info")]
        for f in files:
            src_file = Path(root) / f
            if src_file.suffix in {".db", ".sqlite", ".log", ".pyc"}:
                continue
            if is_git_ignored(src_file, source_root):
                continue
            rel_path = src_file.relative_to(source_root)
            dest_file = target_dir / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)
    return True


def check_server_health(venv_python: Path, repo_dir: Path, port: int) -> bool:
    print(f"[*] Starting server on port {port} and testing /health ...")
    env = os.environ.copy()
    env["AEGIS_SERVER_PORT"] = str(port)
    env["AEGIS_LIVE_BEDROCK"] = "0"

    proc = subprocess.Popen(
        [str(venv_python), "-m", "aegishome.main", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(repo_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    health_url = f"http://127.0.0.1:{port}/health"
    start_time = time.time()
    healthy = False

    try:
        while time.time() - start_time < 15:
            try:
                with urllib.request.urlopen(health_url, timeout=2) as resp:
                    if resp.status == 200:
                        body = json.loads(resp.read().decode())
                        if body.get("status") == "healthy" or "status" in body:
                            healthy = True
                            break
            except Exception:
                time.sleep(0.5)

        if healthy:
            print(f"    [+] PASS: Server responded with HTTP 200 to /health ({time.time() - start_time:.1f}s)")
        else:
            print("    [-] FAIL: Server did not respond with 200 OK within 15 seconds")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    return healthy


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    steps_results: list[tuple[str, str]] = []

    print("=" * 60)
    print("Aegis Fresh Clone & Reproducibility Test")
    print("=" * 60)

    with tempfile.TemporaryDirectory(prefix="aegis_fresh_clone_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        clone_dir = tmp_path / "aegis_repo"
        clone_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: Clone or export
        print(f"[*] Step 1: Cloning repository to {clone_dir} ...")
        t0 = time.time()
        ok = clone_or_export_repo(repo_root, clone_dir)
        has_packages = any(clone_dir.rglob("pyproject.toml"))
        if ok and has_packages:
            print(f"    [+] PASS ({time.time() - t0:.1f}s)")
            steps_results.append(("1. Clone/Export Repo", "PASS"))
        else:
            print("    [-] FAIL: Failed to clone or export repository")
            steps_results.append(("1. Clone/Export Repo", "FAIL"))
            return 1

        # Step 2: Create venv
        venv_dir = clone_dir / ".venv"
        ok, _ = run_command(
            [sys.executable, "-m", "venv", str(venv_dir)],
            cwd=clone_dir,
            description="Step 2: Creating isolated virtualenv",
        )
        steps_results.append(("2. Create Virtualenv", "PASS" if ok else "FAIL"))
        if not ok:
            return 1

        if os.name == "nt":
            venv_python = venv_dir / "Scripts" / "python.exe"
            venv_pytest = venv_dir / "Scripts" / "pytest.exe"
        else:
            venv_python = venv_dir / "bin" / "python"
            venv_pytest = venv_dir / "bin" / "pytest"

        # Step 3: Install packages
        ok, _ = run_command(
            [str(venv_python), "-m", "pip", "install", "-e", "packages/aegis-guard[dev]", "-e", "apps/aegishome[dev]"],
            cwd=clone_dir,
            description="Step 3: Installing packages with dev extras in editable mode",
            timeout=180,
        )
        steps_results.append(("3. Install Packages", "PASS" if ok else "FAIL"))
        if not ok:
            return 1

        # Step 4: Run pytest
        ok, _ = run_command(
            [str(venv_python), "-m", "pytest", "-v"],
            cwd=clone_dir,
            description="Step 4: Running pytest test suite",
            timeout=120,
        )
        steps_results.append(("4. Pytest Suite", "PASS" if ok else "FAIL"))
        if not ok:
            return 1

        # Step 5: Run evals
        ok, _ = run_command(
            [str(venv_python), "apps/aegishome/evals/run_evals.py"],
            cwd=clone_dir,
            description="Step 5: Running adversarial safety evals (61 cases)",
            timeout=120,
        )
        steps_results.append(("5. Safety Evals", "PASS" if ok else "FAIL"))
        if not ok:
            return 1

        # Step 6: Start server and test /health
        port = get_free_port()
        ok = check_server_health(venv_python, clone_dir, port)
        steps_results.append(("6. Server /health Check", "PASS" if ok else "FAIL"))
        if not ok:
            return 1

    print("\n" + "=" * 40)
    print("      FRESH CLONE TEST SUMMARY")
    print("=" * 40)
    all_passed = True
    for name, status in steps_results:
        print(f"  {name:25}: {status}")
        if status != "PASS":
            all_passed = False
    print("=" * 40)

    if all_passed:
        print("[+] SUCCESS: Pristine clone verified end-to-end!")
        return 0
    else:
        print("[-] FAILURE: One or more steps failed during fresh clone test.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
