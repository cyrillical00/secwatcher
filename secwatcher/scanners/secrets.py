"""Secret scanner: invokes trufflehog and gitleaks against a local clone.

Both binaries must be on PATH. The CI workflow installs them; locally, see README.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from secwatcher.models import Finding, FindingType, Severity
from secwatcher.orchestrator import Repository

logger = logging.getLogger(__name__)


class BinaryMissingError(RuntimeError):
    pass


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        env=env or {},
    )


@dataclass
class SecretScanner:
    clone_root: Path
    gitleaks_config: Path | None = None
    full_history: bool = True
    shallow_depth: int = 50
    clone_url_for: Callable[[Repository], str] | None = None
    name: str = "secrets"

    def __post_init__(self) -> None:
        for binary in ("trufflehog", "gitleaks", "git"):
            if shutil.which(binary) is None:
                raise BinaryMissingError(f"Required binary not on PATH: {binary}")

    def scan(self, repo: Repository) -> Iterable[Finding]:
        clone_path = self.clone_root / repo.full_name.replace("/", "_")
        try:
            self._clone(repo, clone_path)
            yield from self._run_trufflehog(repo, clone_path)
            yield from self._run_gitleaks(repo, clone_path)
        finally:
            shutil.rmtree(clone_path, ignore_errors=True)

    def _clone(self, repo: Repository, dest: Path) -> None:
        url = (
            self.clone_url_for(repo)
            if self.clone_url_for is not None
            else getattr(repo, "clone_url", None)
            or f"https://github.com/{repo.full_name}.git"
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--quiet"]
        if not self.full_history:
            cmd += ["--depth", str(self.shallow_depth)]
        cmd += [url, str(dest)]
        result = _run(cmd)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            # Scrub installation token if it leaks into stderr.
            if "x-access-token:" in stderr:
                stderr = "<scrubbed git clone error>"
            raise RuntimeError(f"git clone failed for {repo.full_name}: {stderr}")

    def _run_trufflehog(self, repo: Repository, clone: Path) -> Iterable[Finding]:
        cmd = [
            "trufflehog",
            "git",
            f"file://{clone}",
            "--json",
            "--no-update",
            "--only-verified",
        ]
        if not self.full_history:
            cmd += ["--max-depth", str(self.shallow_depth)]
        result = _run(cmd)
        if result.returncode not in (0, 183):  # 183 = findings present in some versions
            logger.warning("trufflehog exited %s for %s", result.returncode, repo.full_name)
            return
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield self._finding_from_trufflehog(repo, payload)

    def _run_gitleaks(self, repo: Repository, clone: Path) -> Iterable[Finding]:
        report = clone.parent / f"{clone.name}-gitleaks.json"
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(clone),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--no-banner",
        ]
        if self.gitleaks_config:
            cmd.extend(["--config", str(self.gitleaks_config)])
        _run(cmd)
        if not report.exists():
            return
        try:
            payloads = json.loads(report.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        for payload in payloads:
            yield self._finding_from_gitleaks(repo, payload)

    @staticmethod
    def _finding_from_trufflehog(repo: Repository, payload: dict) -> Finding:
        detector = payload.get("DetectorName", "unknown")
        source_meta = payload.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        return Finding(
            repo=repo.full_name,
            finding_type=FindingType.SECRET,
            severity=Severity.CRITICAL,
            rule_id=f"trufflehog/{detector}",
            title=f"Verified {detector} secret",
            file_path=source_meta.get("file"),
            commit_sha=source_meta.get("commit"),
            line=source_meta.get("line"),
            detail="trufflehog confirmed this credential is live.",
            suggested_action="Rotate immediately, then purge from git history.",
        )

    @staticmethod
    def _finding_from_gitleaks(repo: Repository, payload: dict) -> Finding:
        rule = payload.get("RuleID", "unknown")
        return Finding(
            repo=repo.full_name,
            finding_type=FindingType.SECRET,
            severity=Severity.CRITICAL,
            rule_id=f"gitleaks/{rule}",
            title=f"Potential {rule} match",
            file_path=payload.get("File"),
            commit_sha=payload.get("Commit"),
            line=payload.get("StartLine"),
            detail=payload.get("Description"),
            suggested_action="Verify, rotate if real, then suppress or purge history.",
        )
