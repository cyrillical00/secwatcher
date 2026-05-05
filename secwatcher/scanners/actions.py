"""Static auditor for .github/workflows/*.yml. Five misconfig patterns."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable

import yaml

from secwatcher.models import Finding, FindingType, Severity
from secwatcher.orchestrator import Repository

logger = logging.getLogger(__name__)

# Patterns
SECRET_ECHO = re.compile(r"echo\s+.*\$\{\{\s*secrets\.", re.IGNORECASE)
UNTRUSTED_INPUT = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)\.(?:body|title)",
    re.IGNORECASE,
)
SHA_REF = re.compile(r"^[0-9a-f]{40}$")


class ActionsScanner:
    name = "actions"

    def __init__(self, fetch_workflows: Callable[[Repository], dict[str, str]]) -> None:
        """`fetch_workflows(repo) -> {path: yaml_text}`. Injected by orchestrator."""
        self._fetch = fetch_workflows

    def scan(self, repo: Repository) -> Iterable[Finding]:
        try:
            workflows = self._fetch(repo)
        except Exception:
            logger.exception("Failed to fetch workflows for %s", repo.full_name)
            return
        for path, raw in workflows.items():
            yield from self._audit_one(repo, path, raw)

    def _audit_one(self, repo: Repository, path: str, raw: str) -> Iterable[Finding]:
        try:
            doc = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            logger.warning("Bad YAML in %s/%s: %s", repo.full_name, path, exc)
            return

        triggers = doc.get("on") or doc.get(True) or {}  # YAML "on" parses as True
        permissions = doc.get("permissions")
        jobs = doc.get("jobs", {}) or {}

        if permissions == "write-all":
            yield self._f(repo, path, "actions/write-all-permissions", Severity.HIGH,
                          "Workflow grants write-all permissions",
                          "Pin to least-privilege scopes (e.g. contents: read).")

        if isinstance(triggers, dict) and "pull_request_target" in triggers:
            yield self._f(
                repo, path, "actions/pull-request-target", Severity.HIGH,
                "Uses pull_request_target",
                "pull_request_target runs with secrets on untrusted PR code; audit carefully.",
            )

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            runs_on = job.get("runs-on", "")
            if isinstance(runs_on, str) and "self-hosted" in runs_on:
                yield self._f(repo, path, "actions/self-hosted-runner", Severity.MEDIUM,
                              f"Job {job_name} uses self-hosted runner",
                              "Confirm runner isolation; never use on public-fork PRs.")
            for step in job.get("steps", []) or []:
                if not isinstance(step, dict):
                    continue
                yield from self._audit_step(repo, path, job_name, step)

    def _audit_step(self, repo: Repository, path: str, job: str, step: dict) -> Iterable[Finding]:
        run = step.get("run", "")
        if isinstance(run, str) and run:
            if SECRET_ECHO.search(run):
                yield self._f(repo, path, "actions/secret-echo", Severity.HIGH,
                              f"Step in {job} prints a secret",
                              "Do not echo secrets to logs. Use them as env or input only.")
            if UNTRUSTED_INPUT.search(run):
                yield self._f(repo, path, "actions/script-injection", Severity.CRITICAL,
                              f"Step in {job} interpolates untrusted input",
                              "Move PR/issue body into env, then reference $VAR; never inline.")
        uses = step.get("uses")
        if isinstance(uses, str) and "@" in uses:
            ref = uses.rsplit("@", 1)[-1]
            if not SHA_REF.match(ref) and ref not in {"main", "master"} and not ref.startswith("v"):
                pass
            if not SHA_REF.match(ref) and not uses.startswith("./"):
                yield self._f(repo, path, "actions/mutable-action-ref", Severity.MEDIUM,
                              f"Action {uses} pinned to mutable ref",
                              "Pin to a full commit SHA. Tags can be moved.")

    @staticmethod
    def _f(repo: Repository, path: str, rule: str, severity: Severity,
           title: str, action: str) -> Finding:
        return Finding(
            repo=repo.full_name,
            finding_type=FindingType.ACTIONS_MISCONFIG,
            severity=severity,
            rule_id=rule,
            title=title,
            file_path=path,
            suggested_action=action,
        )
