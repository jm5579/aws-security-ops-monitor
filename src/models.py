"""
models.py

Typed data structures shared across the CLI, database layer, and report /
runbook generators. Keeping these as dataclasses (rather than passing raw
dicts around) gives us type-checking, IDE autocomplete, and a single place
to document the shape of a "finding" as it moves through the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Security Hub finding severity labels, ordered low to high."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting, where higher is more severe."""
        order = [
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)


class FindingStatus(str, Enum):
    """Lifecycle status of a finding within the vulnerability register."""

    OPEN = "open"
    IN_REMEDIATION = "in remediation"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted risk"


# Finding "type" is a normalized category derived from the raw Security Hub
# finding title/type, used to select the correct Jinja2 runbook template
# and the correct compliance control mapping.
class FindingType(str, Enum):
    EXPOSED_CREDENTIALS = "exposed_credentials"
    PUBLIC_S3_BUCKET = "public_s3_bucket"
    PERMISSIVE_SECURITY_GROUP = "permissive_security_group"
    EXCESSIVE_IAM_PERMISSIONS = "excessive_iam_permissions"
    UNENCRYPTED_DATA = "unencrypted_data"
    CLOUDTRAIL_LOGGING_FAILURE = "cloudtrail_logging_failure"
    OTHER = "other"


# Maps each normalized finding type to the compliance controls it most
# commonly maps to. This is intentionally a static, hand-curated mapping
# (rather than something fetched at runtime) because compliance mapping
# is a governance decision, not raw telemetry — it should be reviewed and
# version-controlled like any other risk artifact.
COMPLIANCE_MAP: dict[FindingType, dict[str, list[str]]] = {
    FindingType.EXPOSED_CREDENTIALS: {
        "OWASP": ["A07:2021 - Identification and Authentication Failures"],
        "CIS": ["CIS AWS Foundations 1.12", "CIS AWS Foundations 1.14"],
        "NIST": ["NIST 800-53 IA-5", "NIST CSF PR.AC-1"],
        "OSFI_B13": ["B-13 Domain 3: Technology Resilience", "B-13 Domain 4: Cyber Security"],
    },
    FindingType.PUBLIC_S3_BUCKET: {
        "OWASP": ["A01:2021 - Broken Access Control"],
        "CIS": ["CIS AWS Foundations 2.1.5"],
        "NIST": ["NIST 800-53 AC-3", "NIST CSF PR.AC-3"],
        "OSFI_B13": ["B-13 Domain 4: Cyber Security", "B-13 Domain 5: Third-Party Provider"],
    },
    FindingType.PERMISSIVE_SECURITY_GROUP: {
        "OWASP": ["A05:2021 - Security Misconfiguration"],
        "CIS": ["CIS AWS Foundations 5.2", "CIS AWS Foundations 5.3"],
        "NIST": ["NIST 800-53 SC-7", "NIST CSF PR.AC-5"],
        "OSFI_B13": ["B-13 Domain 4: Cyber Security"],
    },
    FindingType.EXCESSIVE_IAM_PERMISSIONS: {
        "OWASP": ["A01:2021 - Broken Access Control"],
        "CIS": ["CIS AWS Foundations 1.16"],
        "NIST": ["NIST 800-53 AC-6", "NIST CSF PR.AC-4"],
        "OSFI_B13": ["B-13 Domain 3: Technology Resilience", "B-13 Domain 4: Cyber Security"],
    },
    FindingType.UNENCRYPTED_DATA: {
        "OWASP": ["A02:2021 - Cryptographic Failures"],
        "CIS": ["CIS AWS Foundations 2.1.1", "CIS AWS Foundations 2.2.1"],
        "NIST": ["NIST 800-53 SC-28", "NIST CSF PR.DS-1"],
        "OSFI_B13": ["B-13 Domain 4: Cyber Security", "B-13 Domain 6: Data Protection"],
    },
    FindingType.CLOUDTRAIL_LOGGING_FAILURE: {
        "OWASP": ["A09:2021 - Security Logging and Monitoring Failures"],
        "CIS": ["CIS AWS Foundations 3.1"],
        "NIST": ["NIST 800-53 AU-2", "NIST CSF DE.AE-3"],
        "OSFI_B13": ["B-13 Domain 4: Cyber Security", "B-13 Domain 7: Incident Response"],
    },
    FindingType.OTHER: {
        "OWASP": [],
        "CIS": [],
        "NIST": [],
        "OSFI_B13": ["B-13 Domain 4: Cyber Security"],
    },
}


@dataclass
class Finding:
    """A normalized security finding, whether sourced from AWS Security Hub,
    GuardDuty, or the mock data generator.

    Attributes:
        finding_id: Stable unique identifier (Security Hub finding ARN, or
            a generated UUID for mock data).
        title: Short human-readable title.
        description: Longer free-text description of the issue.
        severity: Severity label.
        finding_type: Normalized category used for runbook/template selection.
        resource_id: ARN or identifier of the affected AWS resource.
        resource_type: AWS resource type (e.g. "AwsS3Bucket", "AwsIamRole").
        account_id: AWS account ID the finding was raised in.
        region: AWS region the resource lives in.
        source: Originating service ("SecurityHub", "GuardDuty", "CloudTrail").
        detected_at: ISO-8601 timestamp of first detection.
        last_seen_at: ISO-8601 timestamp of most recent observation.
        raw: The original raw finding payload, preserved for audit purposes.
    """

    finding_id: str
    title: str
    description: str
    severity: Severity
    finding_type: FindingType
    resource_id: str
    resource_type: str
    account_id: str
    region: str
    source: str
    detected_at: datetime
    last_seen_at: datetime
    raw: dict[str, Any] | None = None

    def days_open(self, as_of: datetime | None = None) -> int:
        """Compute how many days this finding has been open.

        Args:
            as_of: Reference datetime to compute against; defaults to now.

        Returns:
            Whole number of days between detection and `as_of`.
        """
        reference = as_of or datetime.utcnow()
        return max((reference - self.detected_at).days, 0)

    def compliance_controls(self) -> dict[str, list[str]]:
        """Return the compliance control mapping for this finding's type."""
        return COMPLIANCE_MAP.get(self.finding_type, COMPLIANCE_MAP[FindingType.OTHER])

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (e.g. for DB insertion or templating)."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["finding_type"] = self.finding_type.value
        data["detected_at"] = self.detected_at.isoformat()
        data["last_seen_at"] = self.last_seen_at.isoformat()
        data.pop("raw", None)
        return data
