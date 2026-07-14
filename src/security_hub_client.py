"""
security_hub_client.py

Thin wrapper around boto3 Security Hub / GuardDuty / CloudTrail clients that
converts raw AWS API responses into the normalized `Finding` model used
throughout the rest of the tool.

Design decision: all AWS calls are isolated to this one module. Everything
downstream (the register, the report generator, the runbook generator)
only ever deals with `Finding` objects — so swapping the data source
(mock generator vs real AWS, or later e.g. Wiz/Prisma Cloud) never
requires touching business logic elsewhere.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from src.models import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:  # pragma: no cover
    boto3 = None  # AWS calls will raise a clear error if boto3 isn't installed


class SecurityHubClientError(RuntimeError):
    """Raised when an AWS API call fails in a way the caller should handle."""


# Regex/keyword heuristics used to classify a raw Security Hub finding
# title/type into one of our normalized FindingType categories. Security
# Hub's `Types` field and `Title` are used together because different
# integrations (GuardDuty, Inspector, IAM Access Analyzer, custom) phrase
# things differently.
_CLASSIFICATION_RULES: list[tuple[FindingType, re.Pattern]] = [
    (FindingType.EXPOSED_CREDENTIALS, re.compile(r"credential|secret|access key|exposed key", re.I)),
    (FindingType.PUBLIC_S3_BUCKET, re.compile(r"s3.*public|public.*s3|bucket.*public", re.I)),
    (FindingType.PERMISSIVE_SECURITY_GROUP, re.compile(r"security group|0\.0\.0\.0/0|unrestricted", re.I)),
    (FindingType.EXCESSIVE_IAM_PERMISSIONS, re.compile(r"iam.*(permission|policy|privilege)|excessive", re.I)),
    (FindingType.UNENCRYPTED_DATA, re.compile(r"unencrypted|encryption.*disabled|not encrypted", re.I)),
    (FindingType.CLOUDTRAIL_LOGGING_FAILURE, re.compile(r"cloudtrail|logging.*disabled|audit log", re.I)),
]


def classify_finding_type(title: str, types: list[str]) -> FindingType:
    """Map a raw Security Hub title/type list to a normalized FindingType.

    Args:
        title: The finding's `Title` field.
        types: The finding's `Types` field (list of Security Hub taxonomy
            strings, e.g. ["Software and Configuration Checks/..."]).

    Returns:
        The best-matching FindingType, or FindingType.OTHER if nothing matches.
    """
    haystack = " ".join([title, *types])
    for finding_type, pattern in _CLASSIFICATION_RULES:
        if pattern.search(haystack):
            return finding_type
    return FindingType.OTHER


def _parse_timestamp(value: str | None) -> datetime:
    """Parse a Security Hub ISO-8601 timestamp, defaulting to now if absent.

    Args:
        value: Raw timestamp string from the Security Hub API (may be None).

    Returns:
        A naive UTC datetime.
    """
    if not value:
        return datetime.utcnow()
    try:
        # Security Hub timestamps look like 2024-05-01T12:34:56.789Z
        return datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        logger.warning("Could not parse timestamp %r, defaulting to now", value)
        return datetime.utcnow()


def _normalize_raw_finding(raw: dict[str, Any]) -> Finding:
    """Convert a raw Security Hub `AwsSecurityFinding` dict into a `Finding`.

    Args:
        raw: A single item from the Security Hub `GetFindings` response.

    Returns:
        A normalized Finding instance.
    """
    resources = raw.get("Resources") or [{}]
    primary_resource = resources[0]
    severity_label = (raw.get("Severity") or {}).get("Label", "INFORMATIONAL")

    return Finding(
        finding_id=raw.get("Id", ""),
        title=raw.get("Title", "Untitled finding"),
        description=raw.get("Description", ""),
        severity=Severity(severity_label) if severity_label in Severity.__members__ else Severity.INFORMATIONAL,
        finding_type=classify_finding_type(raw.get("Title", ""), raw.get("Types", [])),
        resource_id=primary_resource.get("Id", "unknown-resource"),
        resource_type=primary_resource.get("Type", "Unknown"),
        account_id=raw.get("AwsAccountId", "unknown-account"),
        region=raw.get("Region", "unknown-region"),
        source="SecurityHub",
        detected_at=_parse_timestamp(raw.get("CreatedAt")),
        last_seen_at=_parse_timestamp(raw.get("UpdatedAt")),
        raw=raw,
    )


class SecurityHubClient:
    """Wrapper for pulling and normalizing findings from AWS Security Hub.

    In production this talks to the real Security Hub `get_findings` API.
    Locally / in a portfolio demo, `USE_MOCK_DATA=true` bypasses this
    entirely in favour of `src.mock_data_generator`.
    """

    def __init__(self, region: str, profile: str | None = None) -> None:
        """
        Args:
            region: AWS region to query Security Hub in.
            profile: Optional named AWS CLI profile.
        """
        self.region = region
        self.profile = profile
        self._client = None

    def _get_client(self):
        """Lazily construct and cache the boto3 Security Hub client.

        Raises:
            SecurityHubClientError: If boto3 is not installed or credentials
                cannot be resolved.
        """
        if self._client is not None:
            return self._client

        if boto3 is None:
            raise SecurityHubClientError(
                "boto3 is not installed. Run `pip install -r requirements.txt`, "
                "or set USE_MOCK_DATA=true to run without AWS credentials."
            )

        try:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            self._client = session.client("securityhub")
        except NoCredentialsError as exc:
            raise SecurityHubClientError(
                "No AWS credentials found. Configure credentials via `aws configure`, "
                "environment variables, or an IAM role, or set USE_MOCK_DATA=true."
            ) from exc
        return self._client

    def fetch_active_findings(
        self, min_severity: str = "LOW", max_results: int = 500
    ) -> list[Finding]:
        """Fetch active (RECORD_STATE=ACTIVE, WORKFLOW_STATUS in NEW/NOTIFIED)
        findings from Security Hub, filtered to a minimum severity.

        Args:
            min_severity: Minimum severity label to include (findings below
                this rank are excluded).
            max_results: Safety cap on the number of findings paginated in.

        Returns:
            List of normalized Finding objects, most recent first.

        Raises:
            SecurityHubClientError: On any AWS API failure, with a clear,
                actionable message (never a raw boto3 traceback leaked to
                the CLI user).
        """
        client = self._get_client()
        min_rank = Severity(min_severity).rank if min_severity in Severity.__members__ else 0

        findings: list[Finding] = []
        next_token: str | None = None

        logger.info("Fetching active Security Hub findings (min severity=%s)", min_severity)

        try:
            while len(findings) < max_results:
                kwargs: dict[str, Any] = {
                    "Filters": {
                        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                        "WorkflowStatus": [
                            {"Value": "NEW", "Comparison": "EQUALS"},
                            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                        ],
                    },
                    "MaxResults": min(100, max_results - len(findings)),
                }
                if next_token:
                    kwargs["NextToken"] = next_token

                response = client.get_findings(**kwargs)
                for raw in response.get("Findings", []):
                    normalized = _normalize_raw_finding(raw)
                    if normalized.severity.rank >= min_rank:
                        findings.append(normalized)

                next_token = response.get("NextToken")
                if not next_token:
                    break

        except (ClientError, BotoCoreError) as exc:
            raise SecurityHubClientError(
                f"Security Hub API call failed: {exc}. Verify that Security Hub is "
                "enabled in this region and that the caller has the "
                "'securityhub:GetFindings' permission."
            ) from exc

        logger.info("Fetched %s active findings from Security Hub", len(findings))
        return findings
