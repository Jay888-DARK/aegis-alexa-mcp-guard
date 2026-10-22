#!/usr/bin/env python3
"""
scripts/check_secrets.py

Scans repository files for leaked credentials, AWS keys, private keys,
and high-entropy secrets before commits or publishing to GitHub.

Checks:
1. AWS Access Key IDs (AKIA / ASIA + 16 chars)
2. aws_secret_access_key assignments
3. PEM private key headers
4. High-entropy candidate secrets in non-test files
"""

from __future__ import annotations

import math
import os
import re
import subprocess
import sys
from pathlib import Path

# Patterns
AWS_KEY_PATTERN = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_PATTERN = re.compile(r"(?i)\baws_secret_access_key\b")
# Private key header pattern (split string to prevent scanner self-matching)
PRIVATE_KEY_PATTERN = re.compile(r"BEGIN(?:\s+[A-Z0-9_-]+)?\s+PRIVATE" + r"\s+KEY")

# High-entropy candidate token pattern: continuous alphanumeric + standard base64/URL safe chars (excluding '=')
CANDIDATE_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/_.-]{30,}")

# Test & tooling file indicators to exclude from entropy check
TEST_INDICATORS = [
    "tests/",
    "tests\\",
    "test_",
    "_test.py",
    "evals/",
    "evals\\",
    "check_secrets.py",  # Don't flag scanner patterns
    ".example",          # Configuration template files
]

# Common false positive patterns for entropy (hex, git hashes, UUIDs, SVG data)
UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_secret(secret: str) -> str:
    """Mask sensitive string keeping first 4 and last 2 characters."""
    if len(secret) <= 6:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 6) + secret[-2:]


def is_test_file(filepath: str) -> bool:
    norm = filepath.replace("\\", "/").lower()
    return any(ind in norm for ind in TEST_INDICATORS)


def is_git_ignored(file_path: Path, repo_root: Path) -> bool:
    """Check if a file is ignored by git."""
    try:
        rel_path = file_path.relative_to(repo_root).as_posix()
        res = subprocess.run(
            ["git", "check-ignore", "-q", rel_path],
            cwd=str(repo_root),
            capture_output=True,
        )
        return res.returncode == 0
    except Exception:
        return False


def get_target_files(repo_root: Path) -> list[Path]:
    """Get tracked files from git ls-files, or fall back to non-ignored files if uncommitted."""
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        tracked = [repo_root / line.strip() for line in result.stdout.splitlines() if line.strip()]
        if tracked:
            return [f for f in tracked if f.is_file()]
    except Exception:
        pass

    # Fallback if no files in git ls-files yet (e.g. fresh repo before initial commit)
    ignored_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", ".idea", ".vscode", "logs"}
    target_files = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.endswith(".egg-info")]
        for f in files:
            p = Path(root) / f
            if p.suffix in {".db", ".sqlite", ".log", ".pyc", ".png", ".jpg", ".ico", ".wasm"}:
                continue
            if is_git_ignored(p, repo_root):
                continue
            target_files.append(p)
    return target_files



def scan_file(file_path: Path, repo_root: Path) -> list[tuple[int, str, str]]:
    """Scan a single file for sensitive patterns. Returns list of (line_no, rule_name, masked_match)."""
    hits = []
    rel_path = file_path.relative_to(repo_root).as_posix()
    if rel_path in {"scripts/check_secrets.py"}:
        return hits
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return hits

    is_test = is_test_file(rel_path)

    for line_idx, line in enumerate(content.splitlines(), start=1):
        # 1. AWS Access Key Pattern
        for m in AWS_KEY_PATTERN.finditer(line):
            hits.append((line_idx, "AWS Access Key", mask_secret(m.group(0))))

        # 2. aws_secret_access_key
        # Ignore comments or purely documentation lines with placeholders like "...
        if AWS_SECRET_PATTERN.search(line):
            # Check if it has a non-placeholder value assigned
            if "=" in line or ":" in line:
                val = line.split("=", 1)[-1] if "=" in line else line.split(":", 1)[-1]
                val = val.strip().strip("'\"")
                if val and val not in {"...", "your_secret_key", "your_secret_access_key", "TODO"}:
                    hits.append((line_idx, "AWS Secret Key Assignment", mask_secret(line.strip())))

        # 3. Private Key Header
        for m in PRIVATE_KEY_PATTERN.finditer(line):
            hits.append((line_idx, "Private Key Header", mask_secret(m.group(0))))

        # 4. Entropy check for non-test files
        if not is_test:
            for token in CANDIDATE_TOKEN_PATTERN.findall(line):
                # Filter out UUIDs, pure hex (e.g., commit SHAs), and common url prefixes
                if UUID_PATTERN.match(token) or HEX_PATTERN.match(token):
                    continue
                if any(token.startswith(p) for p in ("http", "urn:", "file:", "mailto:", "ftp:")):
                    continue
                # Skip file paths with extensions or multiple path segments
                if ("/" in token or "\\" in token) and any(token.endswith(ext) for ext in (".md", ".py", ".html", ".js", ".css", ".json", ".txt", ".toml", ".yaml", ".yml")):
                    continue
                entropy = shannon_entropy(token)
                # Flag high-entropy token (entropy > 4.65 on 32+ length strings)
                if len(token) >= 32 and entropy >= 4.65:
                    hits.append((line_idx, f"High Entropy String (entropy={entropy:.2f})", mask_secret(token)))

    return hits


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    files = get_target_files(repo_root)
    print(f"[*] Scanning {len(files)} files for secrets in {repo_root}...")

    total_hits = 0
    for f in sorted(files):
        hits = scan_file(f, repo_root)
        if hits:
            rel = f.relative_to(repo_root).as_posix()
            for line_no, rule, masked in hits:
                print(f"[!] SECRET FOUND: {rel}:{line_no} [{rule}] -> {masked}")
                total_hits += 1

    if total_hits > 0:
        print(f"\n[-] FAILED: Detected {total_hits} potential secret(s). Please review and remove before committing.")
        return 1

    print("\n[+] PASS: No secrets or credentials detected across tracked files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
