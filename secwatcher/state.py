"""On-disk scan state for incremental --since runs."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

DEFAULT_STATE_PATH = Path.home() / ".secwatcher" / "state.json"


class _RepoLike(Protocol):
    full_name: str
    pushed_at: datetime


@dataclass
class RepoState:
    last_pushed_at: datetime | None = None
    last_scanned_at: datetime | None = None


@dataclass
class StateFile:
    path: Path
    last_scan_at: datetime | None = None
    repos: dict[str, RepoState] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> StateFile:
        path = path or DEFAULT_STATE_PATH
        if not path.exists():
            return cls(path=path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("State file %s unreadable (%s); starting fresh.", path, exc)
            return cls(path=path)
        return cls(
            path=path,
            last_scan_at=_parse_iso(data.get("last_scan_at")),
            repos={
                name: RepoState(
                    last_pushed_at=_parse_iso(rs.get("last_pushed_at")),
                    last_scanned_at=_parse_iso(rs.get("last_scanned_at")),
                )
                for name, rs in (data.get("repos") or {}).items()
            },
        )

    def needs_scan(self, repo: _RepoLike) -> bool:
        prior = self.repos.get(repo.full_name)
        if prior is None or prior.last_scanned_at is None:
            return True
        return repo.pushed_at > prior.last_scanned_at

    def record_scanned(self, repo: _RepoLike) -> None:
        self.repos[repo.full_name] = RepoState(
            last_pushed_at=repo.pushed_at,
            last_scanned_at=datetime.now(UTC),
        )

    def save(self) -> None:
        self.last_scan_at = datetime.now(UTC)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_scan_at": self.last_scan_at.isoformat(),
            "repos": {
                name: {
                    "last_pushed_at": _to_iso(rs.last_pushed_at),
                    "last_scanned_at": _to_iso(rs.last_scanned_at),
                }
                for name, rs in self.repos.items()
            },
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
