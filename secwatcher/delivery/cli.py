"""Terminal and markdown rendering of scan results."""

from __future__ import annotations

from collections.abc import Iterable
from io import StringIO

from rich.console import Console
from rich.table import Table

from secwatcher.models import Finding, ScanResult, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def render_table(findings: Iterable[Finding], console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="Findings", show_lines=False, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Repo", overflow="fold")
    table.add_column("Type", no_wrap=True)
    table.add_column("Rule", overflow="fold")
    table.add_column("Where", overflow="fold")
    table.add_column("Title", overflow="fold")
    for f in findings:
        where = f.file_path or ""
        if f.commit_sha:
            where = f"{where} @ {f.commit_sha[:8]}" if where else f.commit_sha[:8]
        table.add_row(
            f"[{SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
            f.repo,
            f.finding_type.value,
            f.rule_id,
            where,
            f.title,
        )
    console.print(table)


def render_markdown(result: ScanResult) -> str:
    out = StringIO()
    counts = result.counts()
    out.write("# Secwatcher scan report\n\n")
    out.write(f"- Repos scanned: **{result.repos_scanned}**\n")
    out.write(f"- Duration: {result.duration_seconds:.0f}s\n")
    out.write(f"- Started: {result.started_at.isoformat()}\n")
    out.write("- Findings by severity: ")
    out.write(", ".join(f"{s.value} `{counts[s]}`" for s in Severity))
    out.write("\n\n")

    if not result.findings:
        out.write("_No findings._\n")
        return out.getvalue()

    out.write("| Severity | Repo | Type | Rule | Path | Title |\n")
    out.write("|---|---|---|---|---|---|\n")
    for f in result.findings:
        path = f.file_path or ""
        if f.commit_sha:
            path = f"{path} @ `{f.commit_sha[:8]}`" if path else f"`{f.commit_sha[:8]}`"
        out.write(
            f"| {f.severity.value} | `{f.repo}` | {f.finding_type.value} | "
            f"`{f.rule_id}` | {path} | {f.title} |\n"
        )
    return out.getvalue()
