from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

from secwatcher.models import Finding, FindingType, Severity
from secwatcher.orchestrator import Repository

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}


class DependencyVulnScanner:
    """Surfaces CRITICAL/HIGH Dependabot alerts. Skips MEDIUM and lower for noise."""

    name = "deps"

    def __init__(self, fetch_alerts: Callable[[Repository], Iterable[dict[str, Any]]]) -> None:
        self._fetch = fetch_alerts

    def scan(self, repo: Repository) -> Iterable[Finding]:
        try:
            alerts = list(self._fetch(repo))
        except Exception:
            logger.exception("Failed to fetch Dependabot alerts for %s", repo.full_name)
            return

        for alert in alerts:
            if alert.get("state") != "open":
                continue
            advisory = alert.get("security_advisory", {})
            severity_label = (advisory.get("severity") or "").lower()
            severity = SEVERITY_MAP.get(severity_label, Severity.LOW)
            if severity.rank < Severity.HIGH.rank:
                continue
            cve = advisory.get("cve_id") or advisory.get("ghsa_id") or "UNKNOWN"
            package = (alert.get("dependency", {}).get("package", {}) or {}).get("name", "?")
            yield Finding(
                repo=repo.full_name,
                finding_type=FindingType.DEPENDENCY_VULN,
                severity=severity,
                rule_id=f"deps/{cve}",
                title=f"{severity.value} {cve} in {package}",
                file_path=alert.get("dependency", {}).get("manifest_path"),
                detail=advisory.get("summary"),
                suggested_action="Bump the affected dependency to a patched version.",
            )
