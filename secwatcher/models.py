from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]

    @property
    def emoji(self) -> str:
        return {
            "CRITICAL": ":rotating_light:",
            "HIGH": ":warning:",
            "MEDIUM": ":large_orange_diamond:",
            "LOW": ":large_blue_diamond:",
            "INFO": ":information_source:",
        }[self.value]


class FindingType(str, Enum):
    SECRET = "secret"  # noqa: S105 -- enum value, not a credential
    ACTIONS_MISCONFIG = "actions_misconfig"
    BRANCH_PROTECTION = "branch_protection"
    REPO_VISIBILITY = "repo_visibility"
    DEPENDENCY_VULN = "dependency_vuln"


@dataclass(frozen=True)
class Finding:
    repo: str
    finding_type: FindingType
    severity: Severity
    rule_id: str
    title: str
    file_path: str | None = None
    commit_sha: str | None = None
    line: int | None = None
    detail: str | None = None
    suggested_action: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def fingerprint(self) -> str:
        parts = [
            self.repo,
            self.file_path or "",
            self.rule_id,
            self.finding_type.value,
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


@dataclass
class ScanResult:
    started_at: datetime
    finished_at: datetime
    repos_scanned: int
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def counts(self) -> dict[Severity, int]:
        return {sev: len(self.by_severity(sev)) for sev in Severity}
