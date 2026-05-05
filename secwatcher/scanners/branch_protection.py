from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

from secwatcher.models import Finding, FindingType, Severity
from secwatcher.orchestrator import Repository

logger = logging.getLogger(__name__)


class BranchProtectionScanner:
    """Verifies the default branch has minimum protection controls."""

    name = "branch_protection"

    def __init__(
        self,
        fetch_protection: Callable[[Repository], dict[str, Any] | None],
    ) -> None:
        self._fetch = fetch_protection

    def scan(self, repo: Repository) -> Iterable[Finding]:
        if repo.fork:
            return
        try:
            protection = self._fetch(repo)
        except Exception:
            logger.exception("Failed to fetch protection for %s", repo.full_name)
            return

        branch = repo.default_branch
        if protection is None:
            yield self._f(repo, "branch/no-protection", Severity.HIGH,
                          f"{branch} has no branch protection",
                          "Enable required reviews, status checks, and force-push restriction.")
            return

        reviews = (protection.get("required_pull_request_reviews") or {})
        if reviews.get("required_approving_review_count", 0) < 1:
            yield self._f(repo, "branch/no-required-reviews", Severity.MEDIUM,
                          f"{branch} does not require approving reviews",
                          "Require at least 1 approving review on PRs to default branch.")
        if not reviews.get("dismiss_stale_reviews", False):
            yield self._f(repo, "branch/stale-reviews-not-dismissed", Severity.LOW,
                          f"{branch} keeps stale reviews",
                          "Enable dismiss-stale-reviews so new commits invalidate prior approvals.")

        status = protection.get("required_status_checks")
        if not status or not status.get("contexts"):
            yield self._f(repo, "branch/no-status-checks", Severity.MEDIUM,
                          f"{branch} has no required status checks",
                          "Require CI checks to pass before merge.")

        if protection.get("allow_force_pushes", {}).get("enabled", False):
            yield self._f(repo, "branch/force-pushes-allowed", Severity.HIGH,
                          f"{branch} permits force-push",
                          "Disable force-push on default branch.")

    @staticmethod
    def _f(repo: Repository, rule: str, severity: Severity,
           title: str, action: str) -> Finding:
        return Finding(
            repo=repo.full_name,
            finding_type=FindingType.BRANCH_PROTECTION,
            severity=severity,
            rule_id=rule,
            title=title,
            suggested_action=action,
        )
