from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from secwatcher.models import Finding, FindingType, Severity
from secwatcher.orchestrator import Repository

INTERNAL_HINTS = ("internal", "private", "infra", "okta", "gcp", "aws", "secret")


@dataclass
class VisibilityScanner:
    """Heuristic: public repo with no description, no topics, and an internal-sounding name."""

    name: str = "visibility"

    def scan(self, repo: Repository) -> Iterable[Finding]:
        if getattr(repo, "private", False):
            return
        description = (getattr(repo, "description", None) or "").strip()
        topics = getattr(repo, "topics", []) or []
        name = repo.full_name.split("/")[-1].lower()

        if description or topics:
            return
        if not any(hint in name for hint in INTERNAL_HINTS):
            return

        yield Finding(
            repo=repo.full_name,
            finding_type=FindingType.REPO_VISIBILITY,
            severity=Severity.MEDIUM,
            rule_id="visibility/likely-internal-public",
            title=f"Public repo {name} looks like an internal tool",
            suggested_action=(
                "Confirm intent. If internal, set repo to private. "
                "Otherwise add description and topics to dismiss this finding."
            ),
        )
