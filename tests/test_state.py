from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from secwatcher.state import StateFile


@dataclass
class FakeRepo:
    full_name: str
    pushed_at: datetime


def test_load_missing_file_returns_empty(tmp_path):
    state = StateFile.load(tmp_path / "nope.json")
    assert state.repos == {}
    assert state.last_scan_at is None


def test_save_and_reload_round_trip(tmp_path):
    state_path = tmp_path / "state.json"
    state = StateFile.load(state_path)
    repo = FakeRepo("a/b", pushed_at=datetime(2026, 1, 1, tzinfo=UTC))
    state.record_scanned(repo)
    state.save()

    loaded = StateFile.load(state_path)
    assert "a/b" in loaded.repos
    assert loaded.repos["a/b"].last_pushed_at == repo.pushed_at
    assert loaded.last_scan_at is not None


def test_needs_scan_true_for_new_repo(tmp_path):
    state = StateFile.load(tmp_path / "s.json")
    repo = FakeRepo("a/b", pushed_at=datetime.now(UTC))
    assert state.needs_scan(repo) is True


def test_needs_scan_false_when_unchanged(tmp_path):
    state = StateFile.load(tmp_path / "s.json")
    repo = FakeRepo("a/b", pushed_at=datetime(2026, 1, 1, tzinfo=UTC))
    state.record_scanned(repo)
    # last_scanned_at is now > pushed_at, so no further work.
    assert state.needs_scan(repo) is False


def test_needs_scan_true_after_new_push(tmp_path):
    state = StateFile.load(tmp_path / "s.json")
    repo = FakeRepo("a/b", pushed_at=datetime(2026, 1, 1, tzinfo=UTC))
    state.record_scanned(repo)
    later = FakeRepo(
        "a/b", pushed_at=datetime.now(UTC) + timedelta(hours=1)
    )
    assert state.needs_scan(later) is True


def test_corrupt_state_file_recovered(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text("{not valid json", encoding="utf-8")
    state = StateFile.load(state_path)
    assert state.repos == {}
