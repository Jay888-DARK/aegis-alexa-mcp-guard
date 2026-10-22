"""Command-line interface for Aegis Guard.

Supported commands:
    python -m aegis_guard verify-audit [--db PATH]
"""

import argparse
import os
import sys

from aegis_guard.storage import AegisStorage, DEFAULT_DB_PATH


def verify_audit_command(db_path: str | None = None) -> int:
    """Verify hash chain integrity and print diagnostic results."""
    resolved_db = db_path or os.getenv("AEGIS_DB_PATH", DEFAULT_DB_PATH)
    storage = AegisStorage(resolved_db)
    result = storage.verify_chain()
    entries = storage.get_audit_entries()

    print("=======================================================")
    print("  Aegis Guard: Audit Log Integrity Verification")
    print("=======================================================")
    print(f"Database: {resolved_db}")
    print(f"Total Entries: {len(entries)}")

    if result == "OK":
        print("Chain Status: OK")
        print("Integrity: Cryptographically Intact (SHA-256 Verified)")
        return 0
    else:
        print("Chain Status: BROKEN")
        print(f"First Broken Index: {int(result)}")
        if hasattr(result, "row_id"):
            print(f"Database Row ID: {result.row_id}")
        if hasattr(result, "message"):
            print(f"Reason: {result.message}")
        print("Integrity: FAILED (Tampering or Hash Inconsistency Detected)")
        return 1


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m aegis_guard",
        description="Aegis Guard Security Gateway CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    verify_parser = subparsers.add_parser(
        "verify-audit",
        help="Verify the cryptographic SHA-256 hash chain of the audit trail",
    )
    verify_parser.add_argument(
        "--db",
        dest="db_path",
        default=None,
        help="Path to SQLite database (defaults to AEGIS_DB_PATH or ./aegis.db)",
    )

    args = parser.parse_args()

    if args.command == "verify-audit":
        exit_code = verify_audit_command(args.db_path)
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
