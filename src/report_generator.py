"""
report_generator.py

Produces an executive-ready Markdown security report summarizing the
current state of the vulnerability register: open findings by severity,
age distribution, resource type breakdown, and SLA-style aging callouts.

Design decision: Pandas is used here (rather than raw SQL aggregation)
because report generation is inherently a data-analysis task -- grouping,
pivoting, and formatting tabular summaries -- and pandas gives us clean,
testable DataFrame operations plus easy Markdown table rendering.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

# SLA thresholds (days) used to flag aging findings by severity. These
# mirror common risk-appetite policy at financial institutions: critical
# findings are expected to be remediated fastest.
SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH": 14,
    "MEDIUM": 30,
    "LOW": 60,
    "INFORMATIONAL": 90,
}


def _findings_to_dataframe(findings: list[dict]) -> pd.DataFrame:
    """Convert a list of finding dicts into a DataFrame with derived columns.

    Args:
        findings: Finding rows as returned by `VulnerabilityRegister.list_findings`.

    Returns:
        A DataFrame with a `days_open` and `sla_breached` column added.
    """
    df = pd.DataFrame(findings)
    if df.empty:
        return df

    df["detected_at"] = pd.to_datetime(df["detected_at"])
    now = pd.Timestamp.utcnow().tz_localize(None)
    df["days_open"] = (now - df["detected_at"]).dt.days
    df["sla_limit"] = df["severity"].map(SLA_DAYS).fillna(90)
    df["sla_breached"] = df["days_open"] > df["sla_limit"]
    return df


def build_report(findings: list[dict], previous_summary: dict[str, int] | None = None) -> str:
    """Build the full Markdown executive security report.

    Args:
        findings: All findings currently in the register with status
            'open' or 'in remediation' (i.e. still active risk).
        previous_summary: Optional prior severity-count snapshot to show a
            trend line (e.g. from the last report run in CI).

    Returns:
        The rendered Markdown report as a string.
    """
    generated_at = datetime.utcnow().isoformat() + "Z"
    df = _findings_to_dataframe(findings)

    if df.empty:
        return (
            f"# Security Operations Report\n\n"
            f"**Generated:** {generated_at}\n\n"
            f"No open findings in the vulnerability register. \u2705\n"
        )

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    by_severity = (
        df.groupby("severity").size().reindex(severity_order).fillna(0).astype(int)
    )
    by_resource_type = df.groupby("resource_type").size().sort_values(ascending=False)
    sla_breaches = df[df["sla_breached"]].sort_values("days_open", ascending=False)
    oldest = df.sort_values("days_open", ascending=False).head(5)

    lines: list[str] = []
    lines.append("# Security Operations Report")
    lines.append("")
    lines.append(f"**Generated:** {generated_at}")
    lines.append(f"**Total open findings:** {len(df)}")
    lines.append("")

    lines.append("## Summary by Severity")
    lines.append("")
    lines.append("| Severity | Open Findings | Trend |")
    lines.append("|---|---|---|")
    for sev in severity_order:
        count = int(by_severity.get(sev, 0))
        trend = "—"
        if previous_summary is not None:
            prev = previous_summary.get(sev, 0)
            delta = count - prev
            trend = f"+{delta}" if delta > 0 else str(delta) if delta < 0 else "no change"
        lines.append(f"| {sev} | {count} | {trend} |")
    lines.append("")

    lines.append("## Findings by Resource Type")
    lines.append("")
    lines.append("| Resource Type | Open Findings |")
    lines.append("|---|---|")
    for resource_type, count in by_resource_type.items():
        lines.append(f"| {resource_type} | {count} |")
    lines.append("")

    lines.append("## SLA Aging Analysis")
    lines.append("")
    lines.append(
        "Findings are expected to be remediated within severity-based SLA windows "
        f"({', '.join(f'{k}: {v}d' for k, v in SLA_DAYS.items())}). "
        f"**{len(sla_breaches)} finding(s) currently breach their SLA window.**"
    )
    lines.append("")
    if not sla_breaches.empty:
        lines.append("| Finding | Severity | Days Open | SLA (days) | Resource |")
        lines.append("|---|---|---|---|---|")
        for _, row in sla_breaches.head(10).iterrows():
            lines.append(
                f"| {row['title']} | {row['severity']} | {row['days_open']} | "
                f"{int(row['sla_limit'])} | `{row['resource_id']}` |"
            )
        lines.append("")

    lines.append("## Oldest Open Findings")
    lines.append("")
    lines.append("| Finding | Severity | Days Open | Status |")
    lines.append("|---|---|---|---|")
    for _, row in oldest.iterrows():
        lines.append(f"| {row['title']} | {row['severity']} | {row['days_open']} | {row['status']} |")
    lines.append("")

    critical_open = int(by_severity.get("CRITICAL", 0))
    high_open = int(by_severity.get("HIGH", 0))
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"There are currently **{critical_open} critical** and **{high_open} high** "
        f"severity findings open. {len(sla_breaches)} finding(s) are past their "
        "remediation SLA and should be prioritized this cycle. "
        "See the Compliance Mapping section of the README for how these findings "
        "map to OSFI B-13, OWASP, and CIS control frameworks."
    )
    lines.append("")

    return "\n".join(lines)


def save_report(findings: list[dict], output_dir: str, previous_summary: dict[str, int] | None = None) -> str:
    """Build and write the security report to disk.

    Args:
        findings: Active findings to report on.
        output_dir: Directory the report file is written into.
        previous_summary: Optional prior severity snapshot for trend display.

    Returns:
        Full path to the written report file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    content = build_report(findings, previous_summary=previous_summary)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = Path(output_dir) / f"security_report_{timestamp}.md"
    output_path.write_text(content, encoding="utf-8")
    logger.info("Report written to %s", output_path)
    return str(output_path)
