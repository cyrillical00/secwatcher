"""Slack delivery: CRITICAL findings post immediately; rest go in a digest."""

from __future__ import annotations

import logging
from collections.abc import Iterable

import httpx

from secwatcher.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class SlackNotifier:
    def __init__(self, webhook_url: str, *, client: httpx.Client | None = None) -> None:
        self._url = webhook_url
        self._client = client or httpx.Client(timeout=10.0)

    def post_critical(self, finding: Finding) -> None:
        self._post({"blocks": [_finding_block(finding)]})

    def post_digest(self, result: ScanResult, *, exclude: Iterable[Finding] = ()) -> None:
        excluded = {f.fingerprint for f in exclude}
        non_critical = [
            f for f in result.findings
            if f.severity != Severity.CRITICAL and f.fingerprint not in excluded
        ]
        counts = result.counts()
        header = (
            f"*Scan complete*: {result.repos_scanned} repos in {result.duration_seconds:.0f}s\n"
            f"CRITICAL `{counts[Severity.CRITICAL]}` · HIGH `{counts[Severity.HIGH]}` · "
            f"MEDIUM `{counts[Severity.MEDIUM]}` · LOW `{counts[Severity.LOW]}` · "
            f"INFO `{counts[Severity.INFO]}`"
        )
        blocks: list[dict] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": header}},
            {"type": "divider"},
        ]
        for finding in non_critical[:25]:  # cap so we stay under Slack's 50-block limit
            blocks.append(_finding_block(finding))

        if result.errors:
            err_text = "\n".join(f"• {e}" for e in result.errors[:5])
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                          "text": f"*Errors during scan:*\n{err_text}"}})

        self._post({"blocks": blocks})

    def _post(self, payload: dict) -> None:
        try:
            resp = self._client.post(self._url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Slack post failed: %s", exc)


def _finding_block(finding: Finding) -> dict:
    parts = [f"{finding.severity.emoji} *{finding.severity.value}*: `{finding.repo}`"]
    parts.append(f"*{finding.title}*")
    meta_lines = []
    if finding.file_path:
        meta_lines.append(f"path: `{finding.file_path}`")
    if finding.commit_sha:
        meta_lines.append(f"commit: `{finding.commit_sha[:8]}`")
    meta_lines.append(f"rule: `{finding.rule_id}`")
    parts.append(" · ".join(meta_lines))
    if finding.suggested_action:
        parts.append(f"_Action:_ {finding.suggested_action}")
    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": "\n".join(parts)},
    }
