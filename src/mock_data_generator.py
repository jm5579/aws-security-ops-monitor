"""
mock_data_generator.py

Generates realistic, deterministic-ish mock AWS Security Hub findings so the
entire tool (fetch -> register -> triage -> runbook -> report) can be
demoed end-to-end without a live AWS account or active findings.

Design decision: mock findings are built from the *same* six finding-type
templates the runbook generator supports, so a demo always has coverage of
every runbook type — this is what lets `generate-runbook` be shown off
convincingly in an interview.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime, timedelta

from src.models import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

_ACCOUNT_ID = "123456789012"
_REGIONS = ["ca-central-1", "us-east-1"]

# (finding_type, title, description template, resource_type, severity choices)
_MOCK_TEMPLATES: list[tuple[FindingType, str, str, str, list[Severity]]] = [
    (
        FindingType.EXPOSED_CREDENTIALS,
        "IAM access key exposed in public GitHub repository",
        "An active AWS access key belonging to {resource} was found committed "
        "to a public source code repository. The key has not been rotated "
        "since detection and may permit unauthorized API access.",
        "AwsIamAccessKey",
        [Severity.CRITICAL, Severity.HIGH],
    ),
    (
        FindingType.PUBLIC_S3_BUCKET,
        "S3 bucket allows public read access",
        "The bucket policy and/or ACL on {resource} grants public read "
        "access to all objects, potentially exposing sensitive data such as "
        "customer records or application backups to the internet.",
        "AwsS3Bucket",
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
    ),
    (
        FindingType.PERMISSIVE_SECURITY_GROUP,
        "Security group allows unrestricted ingress on sensitive port",
        "Security group {resource} permits inbound traffic from 0.0.0.0/0 on "
        "a sensitive management port, significantly increasing the attack "
        "surface for the associated instances.",
        "AwsEc2SecurityGroup",
        [Severity.HIGH, Severity.MEDIUM],
    ),
    (
        FindingType.EXCESSIVE_IAM_PERMISSIONS,
        "IAM role has excessive administrative permissions",
        "The IAM role {resource} is attached to a policy granting "
        "'Action: *' on 'Resource: *', violating least-privilege principles "
        "and exceeding the access required for its function.",
        "AwsIamRole",
        [Severity.HIGH, Severity.MEDIUM],
    ),
    (
        FindingType.UNENCRYPTED_DATA,
        "EBS volume is not encrypted at rest",
        "Volume {resource} does not have encryption enabled. Data at rest "
        "on this volume, including any application or customer data, is not "
        "protected against unauthorized physical or snapshot access.",
        "AwsEc2Volume",
        [Severity.MEDIUM, Severity.HIGH],
    ),
    (
        FindingType.CLOUDTRAIL_LOGGING_FAILURE,
        "CloudTrail logging is disabled or not delivering logs",
        "Trail {resource} is either disabled or has not delivered log files "
        "to its configured S3 bucket within the expected interval, creating "
        "a gap in the audit trail required for incident investigation.",
        "AwsCloudTrailTrail",
        [Severity.HIGH, Severity.CRITICAL],
    ),
]

_RESOURCE_NAME_POOL = [
    "prod-payments-api", "customer-data-backup", "internal-admin-svc",
    "ci-cd-deploy-role", "legacy-batch-processor", "reporting-warehouse",
    "kyc-document-store", "core-banking-gateway", "fraud-detection-svc",
    "shared-services-vpc",
]


def generate_mock_findings(count: int = 18, seed: int | None = 42) -> list[Finding]:
    """Generate a realistic set of mock Security Hub findings.

    Args:
        count: Number of findings to generate. Values below 6 will still
            guarantee at least one finding of each type.
        seed: Random seed for reproducibility across demo runs. Pass None
            for non-deterministic output.

    Returns:
        List of normalized Finding objects spanning all six finding types
        and a realistic spread of ages and severities.
    """
    rng = random.Random(seed)
    findings: list[Finding] = []
    now = datetime.utcnow()

    # Guarantee at least one of every finding type so runbook demos always
    # have full coverage, then fill the remainder randomly.
    type_cycle = list(_MOCK_TEMPLATES) * ((count // len(_MOCK_TEMPLATES)) + 1)
    rng.shuffle(type_cycle)

    for i in range(count):
        finding_type, title, description_template, resource_type, severities = type_cycle[i]
        resource_name = rng.choice(_RESOURCE_NAME_POOL)
        resource_id = f"arn:aws:{resource_type.lower()}:::{resource_name}-{rng.randint(100,999)}"
        severity = rng.choice(severities)

        # Spread ages from 0 to 45 days so the report's "age" breakdown
        # has something interesting to show (including SLA breaches).
        age_days = rng.choice([0, 1, 3, 7, 14, 21, 30, 45])
        detected_at = now - timedelta(days=age_days)
        last_seen_at = now - timedelta(hours=rng.randint(0, 12))

        findings.append(
            Finding(
                finding_id=str(uuid.uuid4()),
                title=title,
                description=description_template.format(resource=resource_name),
                severity=severity,
                finding_type=finding_type,
                resource_id=resource_id,
                resource_type=resource_type,
                account_id=_ACCOUNT_ID,
                region=rng.choice(_REGIONS),
                source="SecurityHub (mock)",
                detected_at=detected_at,
                last_seen_at=last_seen_at,
            )
        )

    logger.info("Generated %s mock findings across %s finding types", len(findings), len(_MOCK_TEMPLATES))
    return findings
