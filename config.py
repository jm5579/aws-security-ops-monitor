"""
config.py

Central configuration for the AWS Security Operations Monitor.

Design decision: all runtime configuration is resolved from environment
variables first (12-factor style, works cleanly in GitHub Actions secrets)
with sane local-development defaults defined here. Nothing sensitive is
ever hardcoded. A `.env` file (loaded via python-dotenv when present) can
be used for local development; it is git-ignored.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    # Optional: only needed for local dev convenience. In CI/production,
    # real environment variables / GitHub Actions secrets are used instead.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is an optional convenience
    pass


PROJECT_ROOT = Path(__file__).resolve().parent


def _get_bool(env_var: str, default: bool) -> bool:
    """Parse a boolean-like environment variable.

    Args:
        env_var: Name of the environment variable to read.
        default: Value to return if the variable is unset.

    Returns:
        The parsed boolean value.
    """
    raw = os.getenv(env_var)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(env_var: str, default: int) -> int:
    """Parse an integer environment variable, falling back to a default.

    Args:
        env_var: Name of the environment variable to read.
        default: Value to return if the variable is unset or invalid.

    Returns:
        The parsed integer value.
    """
    raw = os.getenv(env_var)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logging.getLogger(__name__).warning(
            "Invalid integer for %s=%r, using default %s", env_var, raw, default
        )
        return default


@dataclass(frozen=True)
class Settings:
    """Immutable application settings resolved at import time.

    Attributes:
        aws_region: AWS region Security Hub / GuardDuty / CloudTrail clients
            should target.
        aws_profile: Optional named AWS CLI profile to use instead of the
            default credential chain. None means "use default chain"
            (env vars, instance role, GitHub OIDC role, etc).
        use_mock_data: When True, the CLI operates entirely on the local
            mock data generator instead of calling real AWS APIs. This lets
            the whole tool be demoed with zero AWS account required.
        db_path: Filesystem path to the SQLite vulnerability register.
        min_severity: Minimum Security Hub severity label to fetch
            ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL").
        max_findings_per_fetch: Safety cap on findings pulled per API call
            to bound cost and runtime.
        report_output_dir: Directory generated reports are written to.
        runbook_output_dir: Directory generated runbooks are written to.
        log_level: Python logging level name.
    """

    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "ca-central-1"))
    aws_profile: str | None = field(default_factory=lambda: os.getenv("AWS_PROFILE"))
    use_mock_data: bool = field(default_factory=lambda: _get_bool("USE_MOCK_DATA", True))
    db_path: str = field(
        default_factory=lambda: os.getenv(
            "VULN_REGISTER_DB_PATH", str(PROJECT_ROOT / "data" / "vulnerability_register.db")
        )
    )
    min_severity: str = field(default_factory=lambda: os.getenv("MIN_SEVERITY", "LOW"))
    max_findings_per_fetch: int = field(
        default_factory=lambda: _get_int("MAX_FINDINGS_PER_FETCH", 500)
    )
    report_output_dir: str = field(
        default_factory=lambda: os.getenv("REPORT_OUTPUT_DIR", str(PROJECT_ROOT / "reports"))
    )
    runbook_output_dir: str = field(
        default_factory=lambda: os.getenv("RUNBOOK_OUTPUT_DIR", str(PROJECT_ROOT / "runbooks"))
    )
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    SEVERITY_ORDER = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def ensure_directories(self) -> None:
        """Create output directories used by the tool if they don't exist."""
        for path in (self.db_path, self.report_output_dir, self.runbook_output_dir):
            Path(path).parent.mkdir(parents=True, exist_ok=True) if path == self.db_path else Path(
                path
            ).mkdir(parents=True, exist_ok=True)


SETTINGS = Settings()


def configure_logging(level: str | None = None) -> None:
    """Configure root logging for the application.

    Uses structured, timestamped log lines to stderr. Called once at CLI
    entrypoint so every module can just use `logging.getLogger(__name__)`.

    Args:
        level: Optional override for the log level; defaults to
            `SETTINGS.log_level`.
    """
    logging.basicConfig(
        level=(level or SETTINGS.log_level).upper(),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
