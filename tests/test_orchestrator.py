from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from secwatcher.models import Finding, FindingType, Severity
from secwatcher.orchestrator import Orchestrator
from secwatcher.suppression import SuppressionRules


@dataclass
class FakeRepo:
    full_name: str
    default_branch: str = "main"
    fork: bool = False
    archived: bool = False
    private: bool = True
    has_push_access: bool = True
    description: str | None = None
    topics: list[str] = field(default_factory=list)
    clone_url: str = "https://example.invalid/repo.git"
    pushed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class FakeScanner:
    def __init__(self, name: str, findings: list[Finding] | Exception) -> None:
        self.name = name
        self._findings = findings

    def scan(self, repo):
        if isinstance(self._findings, Exception):
            raise self._findings
        return list(self._findings)


def _f(repo: str, severity: Severity, rule: str = "r/x", path: str | None = None) -> Finding:
    return Finding(
        repo=repo,
        finding_type=FindingType.SECRET,
        severity=severity,
        rule_id=rule,
        title=f"{rule} in {repo}",
        file_path=path,
    )


def test_archived_repos_skipped():
    repos = [FakeRepo("a/active"), FakeRepo("a/archived", archived=True)]
    scanner = FakeScanner("s", [_f("a/active", Severity.HIGH)])
    orch = Orchestrator(scanners=[scanner], suppression=SuppressionRules())
    result = orch.run(repos)
    assert result.repos_scanned == 1
    assert {f.repo for f in result.findings} == {"a/active"}


def test_findings_sorted_by_severity_desc():
    repo = FakeRepo("x/y")
    findings = [
        _f("x/y", Severity.LOW, rule="r/low"),
        _f("x/y", Severity.CRITICAL, rule="r/crit"),
        _f("x/y", Severity.MEDIUM, rule="r/med"),
    ]
    scanner = FakeScanner("s", findings)
    result = Orchestrator([scanner], SuppressionRules()).run([repo])
    assert [f.severity for f in result.findings] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]


def test_scanner_exception_isolated():
    repo = FakeRepo("x/y")
    good = FakeScanner("ok", [_f("x/y", Severity.HIGH)])
    bad = FakeScanner("boom", RuntimeError("scanner exploded"))
    result = Orchestrator([good, bad], SuppressionRules()).run([repo])
    assert len(result.findings) == 1
    assert any("boom on x/y" in e for e in result.errors)


def test_suppression_applied():
    repo = FakeRepo("x/y")
    findings = [
        _f("x/y", Severity.HIGH, rule="rule/keep"),
        _f("x/y", Severity.HIGH, rule="rule/drop"),
    ]
    scanner = FakeScanner("s", findings)
    rules = SuppressionRules(rule_ids={"rule/drop"})
    result = Orchestrator([scanner], rules).run([repo])
    assert {f.rule_id for f in result.findings} == {"rule/keep"}


def test_critical_filter():
    findings = [_f("a/b", Severity.HIGH), _f("a/b", Severity.CRITICAL)]
    assert [f.severity for f in Orchestrator.critical(findings)] == [Severity.CRITICAL]
