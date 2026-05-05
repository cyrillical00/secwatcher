from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from secwatcher.models import Finding, ScanResult, Severity
from secwatcher.suppression import SuppressionRules

if TYPE_CHECKING:
    from secwatcher.config import Settings
    from secwatcher.github_client import GitHubClient

logger = logging.getLogger(__name__)


class Repository(Protocol):
    """Minimal repo shape used by scanners. Concrete impl is `RepoView` in github_client."""

    full_name: str
    default_branch: str
    fork: bool
    archived: bool
    private: bool
    has_push_access: bool
    description: str | None
    topics: list[str]
    clone_url: str
    pushed_at: datetime


class Scanner(Protocol):
    name: str

    def scan(self, repo: Repository) -> Iterable[Finding]: ...


@dataclass
class Orchestrator:
    scanners: list[Scanner]
    suppression: SuppressionRules

    def run(self, repos: Iterable[Repository]) -> ScanResult:
        started = datetime.now(UTC)
        all_findings: list[Finding] = []
        errors: list[str] = []
        repo_count = 0

        for repo in repos:
            if repo.archived:
                logger.info("Skipping archived repo %s", repo.full_name)
                continue
            repo_count += 1
            for scanner in self.scanners:
                try:
                    for finding in scanner.scan(repo):
                        if self.suppression.is_suppressed(finding):
                            logger.debug(
                                "Suppressed %s in %s (rule=%s)",
                                finding.fingerprint[:12],
                                finding.repo,
                                finding.rule_id,
                            )
                            continue
                        all_findings.append(finding)
                except Exception as exc:
                    errors.append(f"{scanner.name} on {repo.full_name}: {exc}")
                    logger.exception(
                        "Scanner %s failed on %s", scanner.name, repo.full_name
                    )

        all_findings.sort(key=lambda f: (-f.severity.rank, f.repo, f.rule_id))

        return ScanResult(
            started_at=started,
            finished_at=datetime.now(UTC),
            repos_scanned=repo_count,
            findings=all_findings,
            errors=errors,
        )

    @staticmethod
    def critical(findings: Iterable[Finding]) -> list[Finding]:
        return [f for f in findings if f.severity == Severity.CRITICAL]

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        client: GitHubClient,
        clone_root: Path,
        gitleaks_config: Path | None,
        global_suppression: SuppressionRules,
        full_history: bool,
    ) -> Orchestrator:
        """Build the canonical 5-scanner pipeline with all fetchers wired in."""
        # Local imports avoid circular references; orchestrator stays
        # importable without subprocess deps until a scan actually runs.
        from secwatcher.scanners.actions import ActionsScanner
        from secwatcher.scanners.branch_protection import BranchProtectionScanner
        from secwatcher.scanners.deps import DependencyVulnScanner
        from secwatcher.scanners.secrets import SecretScanner
        from secwatcher.scanners.visibility import VisibilityScanner

        scanners: list[Scanner] = [
            SecretScanner(
                clone_root=clone_root,
                gitleaks_config=gitleaks_config,
                full_history=full_history,
                clone_url_for=client.clone_url,
            ),
            ActionsScanner(fetch_workflows=client.fetch_workflows),
            BranchProtectionScanner(fetch_protection=client.fetch_branch_protection),
            VisibilityScanner(),
            DependencyVulnScanner(fetch_alerts=client.fetch_dependabot_alerts),
        ]
        return cls(scanners=scanners, suppression=global_suppression)
