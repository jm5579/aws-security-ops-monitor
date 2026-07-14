"""
runbook_generator.py

Generates structured Markdown incident response runbooks from Jinja2
templates, keyed off a finding's normalized `finding_type`. If a finding
type has no dedicated template (i.e. FindingType.OTHER), a generic fallback
template is used so `generate-runbook` never hard-fails on an unclassified
finding.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# Markdown output, not HTML, so autoescaping is deliberately disabled --
# escaping would corrupt legitimate Markdown syntax (e.g. underscores,
# backticks) in finding titles/descriptions.
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=(), default=False),
    trim_blocks=True,
    lstrip_blocks=True,
)

_GENERIC_TEMPLATE = """\
# Incident Response Runbook: {{ finding.title }}

**Runbook generated:** {{ generated_at }}
**Finding ID:** {{ finding.finding_id }}
**Severity:** {{ finding.severity }}
**Status:** {{ finding.status }}

## 1. Finding Summary
- **Description:** {{ finding.description }}
- **Affected resource:** `{{ finding.resource_id }}` ({{ finding.resource_type }})
- **AWS account:** {{ finding.account_id }} | **Region:** {{ finding.region }}
- **Detected:** {{ finding.detected_at }} ({{ finding.days_open }} days open)

## 2. Immediate Containment Steps
1. Review the finding detail in Security Hub / GuardDuty for service-specific guidance.
2. Restrict access to the affected resource pending investigation if the risk warrants it.

## 3. Root Cause Investigation Steps
1. Review CloudTrail for changes to the affected resource.
2. Identify who/what introduced the condition and when.

## 4. Remediation Procedure
1. Apply the AWS-recommended remediation for this finding type.
2. Update Infrastructure-as-Code sources if applicable to prevent recurrence.

## 5. Verification Steps
- [ ] Confirm the finding no longer appears as ACTIVE in Security Hub.
- [ ] Update the vulnerability register status to `resolved`.

## 6. Lessons Learned Template
- **What happened:**
- **Why it happened (root cause):**
- **Preventive action items:**

---
*Generated automatically by AWS Security Operations Monitor (generic template
— no finding-type-specific runbook was available).*
"""


def generate_runbook(finding: dict) -> str:
    """Render a Markdown incident response runbook for a single finding.

    Args:
        finding: A finding row as returned by `VulnerabilityRegister.get_finding`
            (i.e. a plain dict with keys matching the `findings` table columns).

    Returns:
        The fully rendered Markdown runbook as a string.
    """
    template_name = f"{finding['finding_type']}.j2"
    context = {"finding": finding, "generated_at": datetime.utcnow().isoformat() + "Z"}

    try:
        template = _env.get_template(template_name)
        logger.info("Rendering runbook using template %s", template_name)
    except TemplateNotFound:
        logger.warning(
            "No dedicated template for finding_type=%s, using generic fallback",
            finding["finding_type"],
        )
        template = _env.from_string(_GENERIC_TEMPLATE)

    return template.render(**context)


def save_runbook(finding: dict, output_dir: str) -> str:
    """Render and write a runbook to disk.

    Args:
        finding: Finding dict (see `generate_runbook`).
        output_dir: Directory to write the runbook file into. Created if
            it does not exist.

    Returns:
        The full path to the written runbook file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    content = generate_runbook(finding)
    safe_id = finding["finding_id"].replace("/", "_").replace(":", "_")
    output_path = Path(output_dir) / f"runbook_{safe_id}.md"
    output_path.write_text(content, encoding="utf-8")
    logger.info("Runbook written to %s", output_path)
    return str(output_path)
