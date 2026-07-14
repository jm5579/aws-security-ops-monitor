"""Unit tests for src.db.VulnerabilityRegister."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.db import VulnerabilityRegister
from src.models import Finding, FindingStatus, FindingType, Severity


@pytest.fixture
def register() -> VulnerabilityRegister:
    """Provide a fresh, isolated SQLite register for each test."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "test_register.db")
        reg = VulnerabilityRegister(db_path)
        reg.initialize()
        yield reg


def _make_finding(finding_id: str = "finding-1", severity: Severity = Severity.HIGH) -> Finding:
    """Build a minimal Finding for testing."""
    now = datetime.utcnow()
    return Finding(
        finding_id=finding_id,
        title="Test finding",
        description="Test description",
        severity=severity,
        finding_type=FindingType.PUBLIC_S3_BUCKET,
        resource_id="arn:aws:s3:::test-bucket",
        resource_type="AwsS3Bucket",
        account_id="123456789012",
        region="ca-central-1",
        source="unit-test",
        detected_at=now - timedelta(days=5),
        last_seen_at=now,
    )


def test_initialize_creates_tables(register: VulnerabilityRegister) -> None:
    """initialize() should create the findings table with no rows."""
    assert register.list_findings() == []


def test_upsert_inserts_new_finding(register: VulnerabilityRegister) -> None:
    """Upserting a brand-new finding should insert exactly one row."""
    result = register.upsert_findings([_make_finding()])
    assert result == {"inserted": 1, "updated": 0}
    stored = register.get_finding("finding-1")
    assert stored is not None
    assert stored["status"] == FindingStatus.OPEN.value


def test_upsert_updates_existing_finding(register: VulnerabilityRegister) -> None:
    """Re-upserting the same finding_id should update, not duplicate."""
    register.upsert_findings([_make_finding(severity=Severity.MEDIUM)])
    result = register.upsert_findings([_make_finding(severity=Severity.HIGH)])
    assert result == {"inserted": 0, "updated": 1}

    stored = register.get_finding("finding-1")
    assert stored["severity"] == Severity.HIGH.value
    assert len(register.list_findings()) == 1


def test_mark_resolved_if_missing(register: VulnerabilityRegister) -> None:
    """Findings absent from the latest active set should be auto-resolved."""
    register.upsert_findings([_make_finding("finding-1"), _make_finding("finding-2")])

    resolved_count = register.mark_resolved_if_missing({"finding-1"})
    assert resolved_count == 1

    resolved_finding = register.get_finding("finding-2")
    assert resolved_finding["status"] == FindingStatus.RESOLVED.value
    still_open = register.get_finding("finding-1")
    assert still_open["status"] == FindingStatus.OPEN.value


def test_update_status_sets_resolution_date(register: VulnerabilityRegister) -> None:
    """Transitioning a finding to RESOLVED should populate resolution_date."""
    register.upsert_findings([_make_finding()])
    updated = register.update_status(
        "finding-1", FindingStatus.RESOLVED, owner="secops-team", notes="Bucket policy fixed."
    )
    assert updated is True

    stored = register.get_finding("finding-1")
    assert stored["status"] == FindingStatus.RESOLVED.value
    assert stored["assigned_owner"] == "secops-team"
    assert stored["resolution_date"] is not None


def test_update_status_returns_false_for_unknown_id(register: VulnerabilityRegister) -> None:
    """Updating a nonexistent finding_id should return False, not raise."""
    assert register.update_status("does-not-exist", FindingStatus.RESOLVED) is False


def test_mark_reviewed(register: VulnerabilityRegister) -> None:
    """Marking a finding reviewed should exclude it from unreviewed_only queries."""
    register.upsert_findings([_make_finding()])
    assert len(register.list_findings(unreviewed_only=True)) == 1

    register.mark_reviewed("finding-1")
    assert len(register.list_findings(unreviewed_only=True)) == 0


def test_summary_by_severity(register: VulnerabilityRegister) -> None:
    """summary_by_severity should count only open/in-remediation findings."""
    register.upsert_findings([
        _make_finding("finding-1", Severity.HIGH),
        _make_finding("finding-2", Severity.HIGH),
        _make_finding("finding-3", Severity.CRITICAL),
    ])
    register.update_status("finding-3", FindingStatus.RESOLVED)

    summary = register.summary_by_severity()
    assert summary == {"HIGH": 2}
