"""
cli.py

Command-line entrypoint for the AWS Security Operations Monitor.

Commands:
    fetch-findings    Pull active findings from Security Hub (or mock data)
                       into a JSON snapshot used by update-register.
    update-register   Load the latest snapshot into the SQLite register,
                       inserting new findings and resolving stale ones.
    generate-runbook   Render an incident response runbook for a finding ID.
    generate-report    Produce the executive Markdown security report.
    triage             Interactive-style CLI view of unreviewed findings.

Run `python -m src.cli --help` for full usage.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import SETTINGS, configure_logging
from src.db import VulnerabilityRegister
from src.models import Finding, FindingStatus, FindingType, Severity
from src.runbook_generator import save_runbook
from src.report_generator import save_report, SLA_DAYS
from src.mock_data_generator import generate_mock_findings
from src.security_hub_client import SecurityHubClient, SecurityHubClientError

logger = logging.getLogger(__name__)
console = Console()

SNAPSHOT_PATH = Path(SETTINGS.db_path).parent / "latest_findings_snapshot.json"
PREVIOUS_SUMMARY_PATH = Path(SETTINGS.db_path).parent / "previous_severity_summary.json"

SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFORMATIONAL": "dim",
}


def _finding_from_dict(data: dict) -> Finding:
    """Reconstruct a Finding object from a serialized snapshot dict.

    Args:
        data: Dict as produced by `Finding.to_dict()`.

    Returns:
        A rehydrated Finding instance.
    """
    return Finding(
        finding_id=data["finding_id"],
        title=data["title"],
        description=data["description"],
        severity=Severity(data["severity"]),
        finding_type=FindingType(data["finding_type"]),
        resource_id=data["resource_id"],
        resource_type=data["resource_type"],
        account_id=data["account_id"],
        region=data["region"],
        source=data["source"],
        detected_at=datetime.fromisoformat(data["detected_at"]),
        last_seen_at=datetime.fromisoformat(data["last_seen_at"]),
    )


@click.group()
@click.option("--log-level", default=None, help="Override log level (DEBUG, INFO, WARNING, ERROR).")
def cli(log_level: str | None) -> None:
    """AWS Security Operations Monitor -- vulnerability register, runbooks, and reports."""
    configure_logging(log_level)


@cli.command("fetch-findings")
@click.option("--min-severity", default=None, help="Minimum severity to fetch (overrides config).")
@click.option("--mock/--no-mock", default=None, help="Force mock data on/off (overrides config).")
def fetch_findings(min_severity: str | None, mock: bool | None) -> None:
    """Pull active findings from AWS Security Hub (or mock data) and save a snapshot."""
    use_mock = SETTINGS.use_mock_data if mock is None else mock
    severity_filter = min_severity or SETTINGS.min_severity

    console.print(Panel.fit(
        f"[bold]Fetching findings[/bold]\nSource: {'MOCK DATA' if use_mock else 'AWS Security Hub'}\n"
        f"Minimum severity: {severity_filter}",
        title="fetch-findings",
    ))

    if use_mock:
        findings = generate_mock_findings()
    else:
        try:
            client = SecurityHubClient(region=SETTINGS.aws_region, profile=SETTINGS.aws_profile)
            findings = client.fetch_active_findings(
                min_severity=severity_filter, max_results=SETTINGS.max_findings_per_fetch
            )
        except SecurityHubClientError as exc:
            console.print(f"[bold red]Error fetching findings:[/bold red] {exc}")
            sys.exit(1)

    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8"
    )

    console.print(f"[green]Fetched {len(findings)} findings.[/green] Snapshot saved to {SNAPSHOT_PATH}")
    console.print("Run [bold]update-register[/bold] next to load these into the vulnerability register.")


@cli.command("update-register")
def update_register() -> None:
    """Load the latest fetched snapshot into the SQLite vulnerability register."""
    if not SNAPSHOT_PATH.exists():
        console.print("[bold red]No snapshot found.[/bold red] Run `fetch-findings` first.")
        sys.exit(1)

    raw = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    findings = [_finding_from_dict(d) for d in raw]

    register = VulnerabilityRegister(SETTINGS.db_path)
    register.initialize()

    # Save current severity summary before mutating, for report trend lines.
    previous_summary = register.summary_by_severity()
    PREVIOUS_SUMMARY_PATH.write_text(json.dumps(previous_summary), encoding="utf-8")

    result = register.upsert_findings(findings)
    resolved = register.mark_resolved_if_missing({f.finding_id for f in findings})

    table = Table(title="Vulnerability Register Update")
    table.add_column("Action")
    table.add_column("Count", justify="right")
    table.add_row("New findings inserted", str(result["inserted"]))
    table.add_row("Existing findings updated", str(result["updated"]))
    table.add_row("Findings auto-resolved (no longer active)", str(resolved))
    console.print(table)


@cli.command("generate-runbook")
@click.argument("finding_id")
@click.option("--output-dir", default=None, help="Override runbook output directory.")
def generate_runbook_cmd(finding_id: str, output_dir: str | None) -> None:
    """Generate an incident response runbook for FINDING_ID."""
    register = VulnerabilityRegister(SETTINGS.db_path)
    register.initialize()
    finding = register.get_finding(finding_id)

    if finding is None:
        console.print(f"[bold red]Finding {finding_id} not found in register.[/bold red]")
        console.print("Run `triage` to list known finding IDs.")
        sys.exit(1)

    path = save_runbook(finding, output_dir or SETTINGS.runbook_output_dir)
    console.print(f"[green]Runbook generated:[/green] {path}")


@cli.command("generate-report")
@click.option("--output-dir", default=None, help="Override report output directory.")
def generate_report_cmd(output_dir: str | None) -> None:
    """Generate the executive security report from the current register state."""
    register = VulnerabilityRegister(SETTINGS.db_path)
    register.initialize()

    findings = register.list_findings(status="open") + register.list_findings(status="in remediation")

    previous_summary = None
    if PREVIOUS_SUMMARY_PATH.exists():
        previous_summary = json.loads(PREVIOUS_SUMMARY_PATH.read_text(encoding="utf-8"))

    path = save_report(findings, output_dir or SETTINGS.report_output_dir, previous_summary=previous_summary)
    console.print(f"[green]Report generated:[/green] {path}")

    summary = register.summary_by_severity()
    table = Table(title="Open Findings by Severity")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        count = summary.get(sev, 0)
        table.add_row(f"[{SEVERITY_STYLE[sev]}]{sev}[/]", str(count))
    console.print(table)


@cli.command("triage")
@click.option("--limit", default=20, help="Maximum number of findings to display.")
def triage(limit: int) -> None:
    """Display an interactive-style triage view of unreviewed findings."""
    register = VulnerabilityRegister(SETTINGS.db_path)
    register.initialize()
    findings = register.list_findings(unreviewed_only=True)[:limit]

    if not findings:
        console.print("[green]No unreviewed findings. Register is fully triaged.[/green]")
        return

    table = Table(title=f"Triage Queue ({len(findings)} unreviewed findings)")
    table.add_column("ID", overflow="fold", max_width=10)
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Resource")
    table.add_column("Days Open", justify="right")
    table.add_column("Risk Score", justify="right")

    for f in findings:
        detected = datetime.fromisoformat(f["detected_at"])
        days_open = max((datetime.utcnow() - detected).days, 0)
        risk_score = _risk_score(f["severity"], days_open)
        sev = f["severity"]
        table.add_row(
            f["finding_id"][:8],
            f"[{SEVERITY_STYLE.get(sev, '')}]" + sev + "[/]",
            f["title"],
            f["resource_type"],
            str(days_open),
            str(risk_score),
        )

    console.print(table)
    console.print(
        "\n[dim]Risk score = severity weight x age factor. "
        "Use `generate-runbook <finding_id>` to act on a finding.[/dim]"
    )


def _risk_score(severity: str, days_open: int) -> int:
    """Compute a simple triage risk score combining severity and age.

    Args:
        severity: Severity label string.
        days_open: How many days the finding has been open.

    Returns:
        An integer risk score (higher = more urgent).
    """
    weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFORMATIONAL": 1}
    base = weights.get(severity, 1)
    sla = SLA_DAYS.get(severity, 90)
    age_factor = min(days_open / max(sla, 1), 2.0)  # cap contribution at 2x SLA overrun
    return round(base * (1 + age_factor))


def main() -> None:
    """Console-script entrypoint (see pyproject/setup entry_points)."""
    cli()


if __name__ == "__main__":
    main()
