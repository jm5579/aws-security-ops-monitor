"""Unit tests for src.runbook_generator."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.runbook_generator import generate_runbook, save_runbook

SAMPLE_FINDING = {
    "finding_id": "arn:aws:securityhub:ca-central-1:123456789012:finding/abc-123",
    "title": "S3 bucket allows public read access",
    "description": "The bucket policy grants public read access to all objects.",
    "severity": "CRITICAL",
    "finding_type": "public_s3_bucket",
    "resource_id": "arn:aws:s3:::customer-data-backup-482",
    "resource_type": "AwsS3Bucket",
    "account_id": "123456789012",
    "region": "ca-central-1",
    "source": "SecurityHub",
    "detected_at": "2026-06-20T10:00:00",
    "last_seen_at": "2026-07-10T08:00:00",
    "status": "open",
    "days_open": 23,
}


@pytest.mark.parametrize(
    "finding_type",
    [
        "exposed_credentials",
        "public_s3_bucket",
        "permissive_security_group",
        "excessive_iam_permissions",
        "unencrypted_data",
        "cloudtrail_logging_failure",
    ],
)
def test_generate_runbook_for_each_known_type(finding_type: str) -> None:
    """Every supported finding type should render a non-empty runbook with
    all six required sections present."""
    finding = dict(SAMPLE_FINDING, finding_type=finding_type)
    runbook = generate_runbook(finding)

    assert finding["title"] in runbook
    assert "Immediate Containment Steps" in runbook
    assert "Root Cause Investigation Steps" in runbook
    assert "Remediation Procedure" in runbook
    assert "Verification Steps" in runbook
    assert "Lessons Learned Template" in runbook


def test_generate_runbook_falls_back_for_unknown_type() -> None:
    """An unrecognized finding_type should use the generic fallback template
    rather than raising an exception."""
    finding = dict(SAMPLE_FINDING, finding_type="some_unmapped_type")
    runbook = generate_runbook(finding)
    assert "Incident Response Runbook" in runbook
    assert "generic template" in runbook.lower()


def test_save_runbook_writes_file() -> None:
    """save_runbook should write a Markdown file to the given directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = save_runbook(SAMPLE_FINDING, tmp_dir)
        written = Path(path)
        assert written.exists()
        assert written.suffix == ".md"
        assert "S3 bucket allows public read access" in written.read_text(encoding="utf-8")
