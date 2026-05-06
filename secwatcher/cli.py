"""Typer CLI: init, scan, report."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console

from secwatcher.config import ConfigError, Settings
from secwatcher.delivery.cli import render_markdown, render_table
from secwatcher.delivery.slack import SlackNotifier
from secwatcher.github_client import GitHubClient, RepoView
from secwatcher.models import Finding, ScanResult, Severity
from secwatcher.orchestrator import Orchestrator
from secwatcher.state import DEFAULT_STATE_PATH, StateFile
from secwatcher.suppression import SuppressionRules

app = typer.Typer(
    name="secwatcher",
    help="Autonomous GitHub repository security scanner.",
    no_args_is_help=True,
)

console = Console()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GLOBAL_CONFIG = REPO_ROOT / "config" / ".github-scanner.yml"
DEFAULT_GITLEAKS_CONFIG = REPO_ROOT / "config" / "gitleaks.toml"
DEFAULT_REPORTS_DIR = REPO_ROOT / "reports"
DEFAULT_CLONE_ROOT = Path.home() / ".secwatcher" / "clones"


def _load_settings() -> Settings:
    try:
        return Settings.from_env()
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc


def _load_global_suppression(path: Path) -> SuppressionRules:
    if not path.exists():
        return SuppressionRules()
    return SuppressionRules.from_yaml(path)


def _select_repos(
    client: GitHubClient,
    *,
    only: str | None,
    state: StateFile | None,
) -> Iterator[RepoView]:
    for repo in client.iter_repos(only=only):
        if repo.fork:
            continue
        if state is not None and not state.needs_scan(repo):
            continue
        yield repo


def _deliver(
    settings: Settings,
    result: ScanResult,
    *,
    reports_dir: Path,
) -> None:
    if not settings.slack_webhook:
        raise ConfigError(
            "REPOSENTRY_SLACK_WEBHOOK is not set. Either set it in .env / Actions secrets, "
            "or run with --no-slack to skip Slack delivery."
        )
    notifier = SlackNotifier(settings.slack_webhook)
    criticals = Orchestrator.critical(result.findings)
    for finding in criticals:
        notifier.post_critical(finding)
    notifier.post_digest(result, exclude=criticals)

    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "latest.md").write_text(render_markdown(result), encoding="utf-8")
    (reports_dir / "latest.json").write_text(_result_as_json(result), encoding="utf-8")
    console.print(f"[green]Wrote report to {reports_dir / 'latest.md'}[/]")


def _result_as_json(result: ScanResult) -> str:
    payload = {
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "repos_scanned": result.repos_scanned,
        "errors": result.errors,
        "findings": [_finding_to_dict(f) for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def _finding_to_dict(f: Finding) -> dict:
    return {
        "repo": f.repo,
        "finding_type": f.finding_type.value,
        "severity": f.severity.value,
        "rule_id": f.rule_id,
        "title": f.title,
        "file_path": f.file_path,
        "commit_sha": f.commit_sha,
        "line": f.line,
        "detail": f.detail,
        "suggested_action": f.suggested_action,
        "fingerprint": f.fingerprint,
        "detected_at": f.detected_at.isoformat(),
    }


def _print_summary(result: ScanResult) -> None:
    counts = result.counts()
    summary = " · ".join(f"{s.value} {counts[s]}" for s in Severity)
    console.print(
        f"[bold]Scanned {result.repos_scanned} repos in "
        f"{result.duration_seconds:.0f}s[/]  {summary}"
    )
    if result.errors:
        console.print(f"[yellow]Errors: {len(result.errors)}[/]")
        for err in result.errors[:5]:
            console.print(f"  · {err}")


def _run_scan(
    *,
    full_history: bool,
    only: str | None,
    state_path: Path,
    reports_dir: Path,
    deliver_slack: bool,
) -> ScanResult:
    settings = _load_settings()
    client = GitHubClient(settings)
    state = StateFile.load(state_path)

    global_suppression = _load_global_suppression(DEFAULT_GLOBAL_CONFIG)
    orch = Orchestrator.from_settings(
        settings,
        client=client,
        clone_root=DEFAULT_CLONE_ROOT,
        gitleaks_config=DEFAULT_GITLEAKS_CONFIG,
        global_suppression=global_suppression,
        full_history=full_history,
    )

    selection_state = None if full_history else state
    selected = list(_select_repos(client, only=only, state=selection_state))
    console.print(f"[cyan]Scanning {len(selected)} repos[/] (full_history={full_history})")

    result = orch.run(_record_state(selected, state))
    _print_summary(result)

    if deliver_slack:
        _deliver(settings, result, reports_dir=reports_dir)
    else:
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "latest.md").write_text(render_markdown(result), encoding="utf-8")
        (reports_dir / "latest.json").write_text(_result_as_json(result), encoding="utf-8")

    state.save()
    return result


def _record_state(repos: Iterable[RepoView], state: StateFile) -> Iterator[RepoView]:
    for repo in repos:
        yield repo
        state.record_scanned(repo)


@app.command()
def init(
    repo: str | None = typer.Option(None, "--repo", help="Single repo (owner/name) to scan."),
    state_path: Path = typer.Option(DEFAULT_STATE_PATH, "--state"),
    reports_dir: Path = typer.Option(DEFAULT_REPORTS_DIR, "--reports-dir"),
    no_slack: bool = typer.Option(False, "--no-slack", help="Skip Slack delivery (local smoke)."),
) -> None:
    """Run a full-history baseline scan across all repos."""
    result = _run_scan(
        full_history=True,
        only=repo,
        state_path=state_path,
        reports_dir=reports_dir,
        deliver_slack=not no_slack,
    )
    raise typer.Exit(code=1 if Orchestrator.critical(result.findings) else 0)


@app.command()
def scan(
    repo: str | None = typer.Option(None, "--repo", help="Single repo (owner/name) to scan."),
    state_path: Path = typer.Option(DEFAULT_STATE_PATH, "--state"),
    reports_dir: Path = typer.Option(DEFAULT_REPORTS_DIR, "--reports-dir"),
    no_slack: bool = typer.Option(False, "--no-slack"),
) -> None:
    """Run an incremental scan (only repos pushed since last run)."""
    result = _run_scan(
        full_history=False,
        only=repo,
        state_path=state_path,
        reports_dir=reports_dir,
        deliver_slack=not no_slack,
    )
    raise typer.Exit(code=1 if Orchestrator.critical(result.findings) else 0)


@app.command()
def report(
    fmt: str = typer.Option("table", "--format", help="table | md | json"),
    out: Path | None = typer.Option(None, "--out", help="Write to file (md/json only)."),
    reports_dir: Path = typer.Option(DEFAULT_REPORTS_DIR, "--reports-dir"),
) -> None:
    """Render the latest finding set from reports/latest.json."""
    latest = reports_dir / "latest.json"
    if not latest.exists():
        console.print(f"[yellow]No report at {latest}. Run `secwatcher init` first.[/]")
        raise typer.Exit(code=1)
    payload = json.loads(latest.read_text(encoding="utf-8"))

    if fmt == "table":
        render_table(_findings_from_payload(payload), console=console)
        return
    if fmt == "json":
        text = json.dumps(payload, indent=2)
    elif fmt == "md":
        text = (reports_dir / "latest.md").read_text(encoding="utf-8")
    else:
        console.print(f"[red]Unsupported format: {fmt}[/]")
        raise typer.Exit(code=2)

    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote {out}[/]")
    else:
        console.print(text)


def _findings_from_payload(payload: dict) -> list[Finding]:
    from secwatcher.models import FindingType
    out: list[Finding] = []
    for raw in payload.get("findings", []):
        out.append(
            Finding(
                repo=raw["repo"],
                finding_type=FindingType(raw["finding_type"]),
                severity=Severity(raw["severity"]),
                rule_id=raw["rule_id"],
                title=raw["title"],
                file_path=raw.get("file_path"),
                commit_sha=raw.get("commit_sha"),
                line=raw.get("line"),
                detail=raw.get("detail"),
                suggested_action=raw.get("suggested_action"),
                detected_at=datetime.fromisoformat(raw["detected_at"]),
            )
        )
    return out


if __name__ == "__main__":
    app()
