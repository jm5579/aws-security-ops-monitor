"""Unit tests for src.report_generator."""

from __future__ import annotations

from datetime import datetime, timedelta

from src.report_generator import build_report


def _finding(severity: str, days_ago: int, resource_type: str = "AwsS3Bucket", title: str = "Test finding") -> dict:
    """Build a minimal finding dict for report generation tests."""
    detected = (datetime.utcnow() - timedelta(days=days_ago)).isoformat()
    return {
        "finding_id": f"finding-{title}-{days_ago}",
        "title": title,
        "description": "desc",
        "severity": severity,
        "finding_type": "public_s3_bucket",
        "resource_id": "arn:aws:s3:::bucket",
        "resource_type": resource_type,
        "account_id": "123456789012",
        "region": "ca-central-1",
        "source": "unit-test",
        "detected_at": detected,
        "last_seen_at": detected,
        "status": "open",
    }


def test_build_report_handles_empty_findings() -> None:
    """An empty findings list should produce a clean 'no findings' report."""
    report = build_report([])
    assert "No open findings" in report


def test_build_report_includes_severity_summary() -> None:
    """The severity summary table should reflect the counts passed in."""
    findings = [_finding("CRITICAL", 1), _finding("HIGH", 2), _finding("HIGH", 3)]
    report = build_report(findings)
    assert "Summary by Severity" in report
    assert "CRITICAL" in report
    assert "| HIGH | 2 |" in report


def test_build_report_flags_sla_breaches() -> None:
    """A CRITICAL finding open for 30 days (SLA=7d) should appear in the
    SLA aging analysis section."""
    findings = [_finding("CRITICAL", 30, title="Old critical finding")]
    report = build_report(findings)
    assert "SLA Aging Analysis" in report
    assert "Old critical finding" in report
    assert "1 finding(s) currently breach their SLA window" in report


def test_build_report_shows_trend_when_previous_summary_given() -> None:
    """When a previous severity summary is supplied, the trend column
    should reflect the delta."""
    findings = [_finding("HIGH", 1), _finding("HIGH", 2)]
    report = build_report(findings, previous_summary={"HIGH": 1})
    assert "+1" in report
