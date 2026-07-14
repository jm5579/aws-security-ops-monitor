"""
db.py

SQLite-backed vulnerability register. This is the system of record for all
findings the tool has ever seen, independent of whether they are currently
still reported by Security Hub. Findings that Security Hub stops reporting
are marked "resolved" here rather than deleted, since financial-institution
risk registers require an auditable history, not just current state.

Design decision: plain `sqlite3` (stdlib) rather than an ORM. This keeps
the dependency surface small, makes the schema fully transparent in one
place, and is easy for a reviewer to audit line-by-line — all valuable
properties for a security tool at a regulated institution.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from src.models import Finding, FindingStatus

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id          TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    severity            TEXT NOT NULL,
    finding_type        TEXT NOT NULL,
    resource_id         TEXT NOT NULL,
    resource_type       TEXT NOT NULL,
    account_id          TEXT NOT NULL,
    region              TEXT NOT NULL,
    source              TEXT NOT NULL,
    detected_at         TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    assigned_owner      TEXT,
    remediation_notes   TEXT,
    resolution_date     TEXT,
    compliance_mapping  TEXT,
    reviewed            INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type      ON findings(finding_type);

CREATE TABLE IF NOT EXISTS register_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT NOT NULL,
    event_type      TEXT NOT NULL,   -- 'created' | 'updated' | 'resolved' | 'status_change'
    detail          TEXT,
    occurred_at     TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
"""


class VulnerabilityRegister:
    """Thin data-access layer around the SQLite vulnerability register.

    Usage:
        register = VulnerabilityRegister(db_path)
        register.initialize()
        register.upsert_findings(findings)
    """

    def __init__(self, db_path: str) -> None:
        """
        Args:
            db_path: Filesystem path to the SQLite database file. Parent
                directories are created automatically on `initialize()`.
        """
        self.db_path = db_path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a SQLite connection with row factory and FK enforcement set."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the database file and schema if they do not already exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
        logger.info("Vulnerability register initialized at %s", self.db_path)

    def upsert_findings(self, findings: list[Finding]) -> dict[str, int]:
        """Insert new findings and update existing ones (by finding_id).

        Findings not present in `findings` but currently marked "open" or
        "in remediation" in the DB are left untouched here; resolving them
        is handled separately by `mark_resolved_if_missing` so that a
        partial fetch never accidentally auto-resolves unrelated findings.

        Args:
            findings: Normalized findings pulled from Security Hub/GuardDuty
                or the mock generator.

        Returns:
            Dict with counts: {"inserted": n, "updated": n}.
        """
        now = datetime.utcnow().isoformat()
        inserted = 0
        updated = 0
        with self._connect() as conn:
            for f in findings:
                existing = conn.execute(
                    "SELECT finding_id, status FROM findings WHERE finding_id = ?",
                    (f.finding_id,),
                ).fetchone()
                compliance_json = json.dumps(f.compliance_controls())

                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO findings (
                            finding_id, title, description, severity, finding_type,
                            resource_id, resource_type, account_id, region, source,
                            detected_at, last_seen_at, status, compliance_mapping,
                            reviewed, created_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            f.finding_id, f.title, f.description, f.severity.value,
                            f.finding_type.value, f.resource_id, f.resource_type,
                            f.account_id, f.region, f.source,
                            f.detected_at.isoformat(), f.last_seen_at.isoformat(),
                            FindingStatus.OPEN.value, compliance_json, 0, now, now,
                        ),
                    )
                    conn.execute(
                        "INSERT INTO register_events (finding_id, event_type, detail, occurred_at) "
                        "VALUES (?, 'created', ?, ?)",
                        (f.finding_id, f"New {f.severity.value} finding ingested from {f.source}", now),
                    )
                    inserted += 1
                else:
                    conn.execute(
                        """
                        UPDATE findings SET
                            title = ?, description = ?, severity = ?, finding_type = ?,
                            resource_id = ?, resource_type = ?, last_seen_at = ?,
                            compliance_mapping = ?, updated_at = ?
                        WHERE finding_id = ?
                        """,
                        (
                            f.title, f.description, f.severity.value, f.finding_type.value,
                            f.resource_id, f.resource_type, f.last_seen_at.isoformat(),
                            compliance_json, now, f.finding_id,
                        ),
                    )
                    conn.execute(
                        "INSERT INTO register_events (finding_id, event_type, detail, occurred_at) "
                        "VALUES (?, 'updated', 'Finding re-observed by scanner', ?)",
                        (f.finding_id, now),
                    )
                    updated += 1

        logger.info("Register upsert complete: %s inserted, %s updated", inserted, updated)
        return {"inserted": inserted, "updated": updated}

    def mark_resolved_if_missing(self, active_finding_ids: set[str]) -> int:
        """Mark findings as resolved if they are open in the DB but were not
        present in the latest fetch from Security Hub (i.e. AWS no longer
        reports them as active).

        Args:
            active_finding_ids: Set of finding_ids returned by the most
                recent fetch.

        Returns:
            Number of findings transitioned to 'resolved'.
        """
        now = datetime.utcnow().isoformat()
        resolved_count = 0
        with self._connect() as conn:
            open_rows = conn.execute(
                "SELECT finding_id FROM findings WHERE status IN (?, ?)",
                (FindingStatus.OPEN.value, FindingStatus.IN_REMEDIATION.value),
            ).fetchall()
            for row in open_rows:
                if row["finding_id"] not in active_finding_ids:
                    conn.execute(
                        "UPDATE findings SET status = ?, resolution_date = ?, updated_at = ? "
                        "WHERE finding_id = ?",
                        (FindingStatus.RESOLVED.value, now, now, row["finding_id"]),
                    )
                    conn.execute(
                        "INSERT INTO register_events (finding_id, event_type, detail, occurred_at) "
                        "VALUES (?, 'resolved', 'No longer reported as active by source', ?)",
                        (row["finding_id"], now),
                    )
                    resolved_count += 1
        if resolved_count:
            logger.info("Auto-resolved %s findings no longer active in source", resolved_count)
        return resolved_count

    def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
        owner: str | None = None,
        notes: str | None = None,
    ) -> bool:
        """Update the workflow status/ownership/notes of a single finding.

        Args:
            finding_id: The finding to update.
            status: New status value.
            owner: Optional assigned owner (e.g. "secops-team").
            notes: Optional free-text remediation notes.

        Returns:
            True if a row was updated, False if the finding_id was not found.
        """
        now = datetime.utcnow().isoformat()
        resolution_date = now if status == FindingStatus.RESOLVED else None
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE findings
                SET status = ?,
                    assigned_owner = COALESCE(?, assigned_owner),
                    remediation_notes = COALESCE(?, remediation_notes),
                    resolution_date = COALESCE(?, resolution_date),
                    updated_at = ?
                WHERE finding_id = ?
                """,
                (status.value, owner, notes, resolution_date, now, finding_id),
            )
            if cur.rowcount:
                conn.execute(
                    "INSERT INTO register_events (finding_id, event_type, detail, occurred_at) "
                    "VALUES (?, 'status_change', ?, ?)",
                    (finding_id, f"Status changed to {status.value}", now),
                )
            return cur.rowcount > 0

    def mark_reviewed(self, finding_id: str) -> bool:
        """Flag a finding as having been triaged by an analyst.

        Args:
            finding_id: The finding to mark reviewed.

        Returns:
            True if a row was updated.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE findings SET reviewed = 1, updated_at = ? WHERE finding_id = ?",
                (datetime.utcnow().isoformat(), finding_id),
            )
            return cur.rowcount > 0

    def get_finding(self, finding_id: str) -> dict | None:
        """Fetch a single finding by ID.

        Args:
            finding_id: The finding to fetch.

        Returns:
            A dict representation of the row, or None if not found.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        unreviewed_only: bool = False,
    ) -> list[dict]:
        """Query findings with optional filters.

        Args:
            status: Filter by status (open, in remediation, resolved, accepted risk).
            severity: Filter by severity label.
            unreviewed_only: If True, only return findings not yet triaged.

        Returns:
            List of matching findings as dicts, most severe / oldest first.
        """
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[str] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if unreviewed_only:
            query += " AND reviewed = 0"
        query += " ORDER BY detected_at ASC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def summary_by_severity(self) -> dict[str, int]:
        """Count open findings grouped by severity.

        Returns:
            Dict mapping severity label -> count of open findings.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt FROM findings
                WHERE status IN ('open', 'in remediation')
                GROUP BY severity
                """
            ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}
