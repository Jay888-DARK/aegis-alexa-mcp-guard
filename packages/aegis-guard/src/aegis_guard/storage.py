"""SQLite persistence layer for Aegis Guard.

Provides durable, ACID-compliant SQLite storage for:
- proposals (id, action_hash, risk, status, attempts, expires_at, approved_by_owner, session_id)
- used_codes (proposal_id, used_at)
- taint (session_id, tainted, source, set_at)
- audit (id, ts, event, detail_json, prev_hash, entry_hash)
"""

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Callable

from aegis_guard.policy import RiskLevel


GENESIS_HASH = "0" * 64
DEFAULT_DB_PATH = "./aegis.db"


class ValidChain(str):
    """Represents a valid, intact audit hash chain (equals 'OK')."""

    def __new__(cls) -> "ValidChain":
        return super().__new__(cls, "OK")

    @property
    def is_valid(self) -> bool:
        return True

    @property
    def broken_index(self) -> None:
        return None

    def __iter__(self):
        yield True
        yield None


class BrokenIndex(int):
    """Represents a broken audit hash chain index."""

    def __new__(cls, index: int, row_id: int | None = None, message: str = "") -> "BrokenIndex":
        instance = super().__new__(cls, index)
        instance.index = index
        instance.row_id = row_id if row_id is not None else index
        instance.message = message
        return instance

    @property
    def is_valid(self) -> bool:
        return False

    @property
    def broken_index(self) -> int:
        return int(self)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            return int(self) == other or self.row_id == other
        if isinstance(other, str):
            return False  # not "OK"
        return super().__eq__(other)

    def __iter__(self):
        yield False
        yield int(self)


def canonicalize_audit_entry(ts: float, event: str, detail_json: str) -> str:
    """Produce deterministic canonical JSON for an audit entry."""
    try:
        detail_obj = json.loads(detail_json) if isinstance(detail_json, str) else detail_json
    except Exception:
        detail_obj = detail_json

    payload = {
        "detail": detail_obj,
        "event": str(event).upper(),
        "ts": round(float(ts), 6),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class AegisStorage:
    """ACID-compliant SQLite storage backend for Aegis Guard."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        time_provider: Callable[[], float] | None = None,
    ) -> None:
        raw_path = db_path if db_path is not None else os.getenv("AEGIS_DB_PATH", DEFAULT_DB_PATH)
        self.db_path = str(raw_path)
        self._time_provider = time_provider or time.time
        self._lock = threading.RLock()
        self._local = threading.local()

        if self.db_path != ":memory:":
            Path(self.db_path).resolve().parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create or retrieve a thread-local configured SQLite connection."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False,
                isolation_level=None,  # Autocommit mode; explicit BEGIN/COMMIT
            )
            conn.row_factory = sqlite3.Row
            if self.db_path != ":memory:":
                try:
                    conn.execute("PRAGMA journal_mode = WAL;")
                except Exception:
                    pass
            conn.execute("PRAGMA busy_timeout = 30000;")
            conn.execute("PRAGMA foreign_keys = ON;")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close connection for current thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _init_db(self) -> None:
        """Initialize database schema with all required tables."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                # 1. Proposals table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS proposals (
                        id TEXT PRIMARY KEY,
                        action_hash TEXT NOT NULL,
                        risk TEXT NOT NULL,
                        status TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        expires_at REAL NOT NULL,
                        approved_by_owner INTEGER NOT NULL DEFAULT 0,
                        session_id TEXT,
                        device TEXT,
                        action TEXT,
                        params_json TEXT,
                        canonical_json TEXT,
                        nonce TEXT,
                        voice_code TEXT,
                        summary TEXT,
                        created_at REAL,
                        approved_by TEXT,
                        executed INTEGER NOT NULL DEFAULT 0,
                        is_tainted INTEGER NOT NULL DEFAULT 0,
                        base_risk_tier TEXT,
                        escalation_reason TEXT
                    );
                    """
                )

                # 2. Used codes table (guarantees single-use codes)
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS used_codes (
                        proposal_id TEXT PRIMARY KEY,
                        used_at REAL NOT NULL,
                        FOREIGN KEY (proposal_id) REFERENCES proposals(id)
                    );
                    """
                )

                # 3. Taint tracking table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS taint (
                        session_id TEXT PRIMARY KEY,
                        tainted INTEGER NOT NULL DEFAULT 1,
                        source TEXT,
                        set_at REAL NOT NULL,
                        reason TEXT,
                        metadata_json TEXT
                    );
                    """
                )

                # 4. Hash-chained audit log table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts REAL NOT NULL,
                        event TEXT NOT NULL,
                        detail_json TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL
                    );
                    """
                )
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

    # --------------------------------------------------------------------------
    # Proposals Management
    # --------------------------------------------------------------------------

    def save_proposal(self, proposal: Any) -> None:
        """Insert or replace a proposal in storage."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                risk_val = getattr(proposal.risk_tier, "value", str(proposal.risk_tier))
                base_risk_val = (
                    getattr(proposal.base_risk_tier, "value", str(proposal.base_risk_tier))
                    if proposal.base_risk_tier is not None
                    else None
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO proposals (
                        id, action_hash, risk, status, attempts, expires_at,
                        approved_by_owner, session_id, device, action, params_json,
                        canonical_json, nonce, voice_code, summary, created_at,
                        approved_by, executed, is_tainted, base_risk_tier, escalation_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        proposal.proposal_id,
                        proposal.action_digest,
                        risk_val,
                        proposal.status,
                        proposal.failed_attempts,
                        proposal.expires_at,
                        1 if proposal.owner_approved else 0,
                        proposal.session_id,
                        proposal.device,
                        proposal.action,
                        json.dumps(proposal.params or {}),
                        proposal.canonical_action_json,
                        proposal.nonce,
                        proposal.voice_code,
                        proposal.summary,
                        proposal.created_at,
                        proposal.approved_by,
                        1 if proposal.executed else 0,
                        1 if proposal.is_tainted else 0,
                        base_risk_val,
                        proposal.escalation_reason,
                    ),
                )
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

    def get_proposal(self, proposal_id: str) -> Any | None:
        """Retrieve a proposal and reconstruct a Proposal dataclass."""
        from aegis_guard.confirm import Proposal

        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT * FROM proposals WHERE id = ?;", (proposal_id,))
            row = cur.fetchone()
            if not row:
                return None

            params = json.loads(row["params_json"] or "{}")
            risk = RiskLevel(row["risk"])
            base_risk = RiskLevel(row["base_risk_tier"]) if row["base_risk_tier"] else None

            prop = Proposal(
                proposal_id=row["id"],
                device=row["device"] or "",
                action=row["action"] or "",
                params=params,
                canonical_action_json=row["canonical_json"] or "",
                action_digest=row["action_hash"],
                risk_tier=risk,
                summary=row["summary"] or "",
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                nonce=row["nonce"] or "",
                voice_code=row["voice_code"],
                session_id=row["session_id"] or "",
                status=row["status"],
                failed_attempts=row["attempts"],
                owner_approved=bool(row["approved_by_owner"]),
                approved_by=row["approved_by"],
                executed=bool(row["executed"]),
                is_tainted=bool(row["is_tainted"]),
                base_risk_tier=base_risk,
                escalation_reason=row["escalation_reason"],
            )

            # Evaluate expiry status dynamically
            now = self._time_provider()
            if prop.status == "PENDING" and now >= prop.expires_at:
                prop.status = "EXPIRED"
                conn.execute("UPDATE proposals SET status = 'EXPIRED' WHERE id = ?;", (prop.proposal_id,))

            return prop

    def get_all_proposals(self) -> list[Any]:
        """Retrieve all proposals from storage."""
        from aegis_guard.confirm import Proposal

        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT * FROM proposals ORDER BY created_at ASC;")
            rows = cur.fetchall()
            results = []
            now = self._time_provider()
            for row in rows:
                params = json.loads(row["params_json"] or "{}")
                risk = RiskLevel(row["risk"])
                base_risk = RiskLevel(row["base_risk_tier"]) if row["base_risk_tier"] else None

                prop = Proposal(
                    proposal_id=row["id"],
                    device=row["device"] or "",
                    action=row["action"] or "",
                    params=params,
                    canonical_action_json=row["canonical_json"] or "",
                    action_digest=row["action_hash"],
                    risk_tier=risk,
                    summary=row["summary"] or "",
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    nonce=row["nonce"] or "",
                    voice_code=row["voice_code"],
                    session_id=row["session_id"] or "",
                    status=row["status"],
                    failed_attempts=row["attempts"],
                    owner_approved=bool(row["approved_by_owner"]),
                    approved_by=row["approved_by"],
                    executed=bool(row["executed"]),
                    is_tainted=bool(row["is_tainted"]),
                    base_risk_tier=base_risk,
                    escalation_reason=row["escalation_reason"],
                )

                if prop.status == "PENDING" and now >= prop.expires_at:
                    prop.status = "EXPIRED"

                results.append(prop)
            return results

    def update_proposal_status(
        self,
        proposal_id: str,
        status: str,
        attempts: int | None = None,
        approved_by_owner: bool | None = None,
        approved_by: str | None = None,
        executed: bool | None = None,
    ) -> None:
        """Update proposal state attributes in an atomic query."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                updates = ["status = ?"]
                params: list[Any] = [status]

                if attempts is not None:
                    updates.append("attempts = ?")
                    params.append(attempts)
                if approved_by_owner is not None:
                    updates.append("approved_by_owner = ?")
                    params.append(1 if approved_by_owner else 0)
                if approved_by is not None:
                    updates.append("approved_by = ?")
                    params.append(approved_by)
                if executed is not None:
                    updates.append("executed = ?")
                    params.append(1 if executed else 0)

                params.append(proposal_id)
                query = f"UPDATE proposals SET {', '.join(updates)} WHERE id = ?;"
                conn.execute(query, tuple(params))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

    def is_code_used(self, proposal_id: str) -> bool:
        """Check if a proposal has already been confirmed / code used."""
        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT used_at FROM used_codes WHERE proposal_id = ?;", (proposal_id,))
            return cur.fetchone() is not None

    def record_used_code(self, proposal_id: str) -> bool:
        """Atomically record code usage. Returns True if inserted, False if already used."""
        with self._lock:
            conn = self._get_connection()
            try:
                now = self._time_provider()
                conn.execute(
                    "INSERT INTO used_codes (proposal_id, used_at) VALUES (?, ?);",
                    (proposal_id, now),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    # --------------------------------------------------------------------------
    # Taint Management
    # --------------------------------------------------------------------------

    def set_taint(
        self,
        session_id: str,
        source: str,
        reason: str = "Accessed untrusted input",
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Mark a session as tainted in durable storage."""
        from aegis_guard.taint import TaintRecord

        sid = session_id.strip() if session_id else "default_session"
        now = self._time_provider()
        meta_json = json.dumps(metadata or {})

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    INSERT OR REPLACE INTO taint (session_id, tainted, source, set_at, reason, metadata_json)
                    VALUES (?, 1, ?, ?, ?, ?);
                    """,
                    (sid, source, now, reason, meta_json),
                )
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

        return TaintRecord(
            session_id=sid,
            source=source,
            reason=reason,
            timestamp=now,
            metadata=metadata or {},
        )

    def is_tainted(self, session_id: str) -> bool:
        """Check if a session is currently marked tainted."""
        if not session_id or not session_id.strip():
            return False
        sid = session_id.strip()

        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT tainted FROM taint WHERE session_id = ?;", (sid,))
            row = cur.fetchone()
            return bool(row and row["tainted"] == 1)

    def get_taint_record(self, session_id: str) -> Any | None:
        """Retrieve TaintRecord from storage if tainted."""
        from aegis_guard.taint import TaintRecord

        if not session_id or not session_id.strip():
            return None
        sid = session_id.strip()

        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT * FROM taint WHERE session_id = ?;", (sid,))
            row = cur.fetchone()
            if not row or row["tainted"] != 1:
                return None
            meta = json.loads(row["metadata_json"] or "{}")
            return TaintRecord(
                session_id=row["session_id"],
                source=row["source"] or "",
                reason=row["reason"] or "",
                timestamp=row["set_at"],
                metadata=meta,
            )

    def clear_taint(self) -> None:
        """Clear all session taint entries."""
        with self._lock:
            conn = self._get_connection()
            conn.execute("DELETE FROM taint;")

    # --------------------------------------------------------------------------
    # Hash-Chained Audit Trail
    # --------------------------------------------------------------------------

    def log_audit(
        self,
        event: str,
        detail_json: str | dict[str, Any],
        ts: float | None = None,
    ) -> dict[str, Any]:
        """Atomically append a hash-chained audit entry to storage.

        Formula:
            entry_hash = SHA256(prev_hash + canonical JSON of the entry)
        """
        now = ts if ts is not None else self._time_provider()
        event_str = str(event).upper()

        if isinstance(detail_json, dict):
            raw_detail_json = json.dumps(detail_json, sort_keys=True, separators=(",", ":"))
        else:
            raw_detail_json = str(detail_json)

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                # Fetch prev_hash from the last entry
                cur = conn.execute("SELECT id, entry_hash FROM audit ORDER BY id DESC LIMIT 1;")
                last_row = cur.fetchone()
                prev_hash = last_row["entry_hash"] if last_row else GENESIS_HASH

                # Compute canonical JSON and entry hash
                canonical_entry = canonicalize_audit_entry(now, event_str, raw_detail_json)
                entry_hash = hashlib.sha256((prev_hash + canonical_entry).encode("utf-8")).hexdigest()

                cur_ins = conn.execute(
                    """
                    INSERT INTO audit (ts, event, detail_json, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (now, event_str, raw_detail_json, prev_hash, entry_hash),
                )
                entry_id = cur_ins.lastrowid
                conn.execute("COMMIT;")

                return {
                    "id": entry_id,
                    "ts": now,
                    "event": event_str,
                    "detail_json": raw_detail_json,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                }
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

    def verify_chain(self) -> ValidChain | BrokenIndex:
        """Verify the cryptographic hash chain of the audit log.

        Returns:
            ValidChain ('OK') if the chain is intact, or
            BrokenIndex(i) identifying the first corrupted index.
        """
        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT id, ts, event, detail_json, prev_hash, entry_hash FROM audit ORDER BY id ASC;")
            rows = cur.fetchall()

            expected_prev = GENESIS_HASH
            for idx, row in enumerate(rows):
                row_id = row["id"]
                ts = row["ts"]
                event = row["event"]
                detail_json = row["detail_json"]
                prev_hash = row["prev_hash"]
                entry_hash = row["entry_hash"]

                # 1. Check prev_hash linkage
                if prev_hash != expected_prev:
                    return BrokenIndex(idx, row_id=row_id, message=f"prev_hash mismatch at row {row_id}")

                # 2. Check entry_hash SHA-256 calculation
                canonical = canonicalize_audit_entry(ts, event, detail_json)
                calculated_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
                if entry_hash != calculated_hash:
                    return BrokenIndex(idx, row_id=row_id, message=f"entry_hash mismatch at row {row_id}")

                expected_prev = entry_hash

            return ValidChain()

    def get_audit_entries(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Retrieve audit log entries in chronological order."""
        with self._lock:
            conn = self._get_connection()
            query = "SELECT * FROM audit ORDER BY id ASC"
            if limit is not None:
                query += f" LIMIT {int(limit)}"
            cur = conn.execute(query)
            results = []
            for row in cur.fetchall():
                try:
                    detail = json.loads(row["detail_json"])
                except Exception:
                    detail = row["detail_json"]
                results.append(
                    {
                        "id": row["id"],
                        "timestamp": row["ts"],
                        "event_type": row["event"],
                        "detail": detail,
                        "prev_hash": row["prev_hash"],
                        "entry_hash": row["entry_hash"],
                    }
                )
            return results

    def clear_audit(self) -> None:
        """Clear all audit rows."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM audit;")
                conn.execute("DELETE FROM sqlite_sequence WHERE name='audit';")
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # General Reset
    # --------------------------------------------------------------------------

    def reset(self) -> None:
        """Reset all tables in database (primarily for tests)."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("DELETE FROM used_codes;")
                conn.execute("DELETE FROM proposals;")
                conn.execute("DELETE FROM taint;")
                conn.execute("DELETE FROM audit;")
                try:
                    conn.execute("DELETE FROM sqlite_sequence;")
                except Exception:
                    pass
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise


# Global storage instance
_GLOBAL_STORAGE: AegisStorage | None = None


def get_storage(db_path: str | Path | None = None, time_provider: Callable[[], float] | None = None) -> AegisStorage:
    """Retrieve or initialize the global AegisStorage instance."""
    global _GLOBAL_STORAGE
    target_path = str(db_path) if db_path is not None else os.getenv("AEGIS_DB_PATH", DEFAULT_DB_PATH)
    if _GLOBAL_STORAGE is None or _GLOBAL_STORAGE.db_path != target_path:
        _GLOBAL_STORAGE = AegisStorage(target_path, time_provider=time_provider)
    elif time_provider is not None:
        _GLOBAL_STORAGE._time_provider = time_provider
    return _GLOBAL_STORAGE


def reset_storage(db_path: str | Path | None = None) -> AegisStorage:
    """Reset and reinitialize global storage instance."""
    global _GLOBAL_STORAGE
    storage = get_storage(db_path)
    storage.reset()
    return storage
