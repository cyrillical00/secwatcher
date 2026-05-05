from __future__ import annotations

import base64

import httpx
import pytest

from secwatcher.config import Settings
from secwatcher.github_client import GitHubClient, _next_link


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_id="123",
        installation_id="456",
        private_key="dummy-key",
        slack_webhook="https://hooks.slack.invalid/x",
        owner=None,
    )


@pytest.fixture
def client(settings: Settings) -> GitHubClient:
    """Routes match by (a) full URL exact, or (b) path + query-key set.

    A path-only entry MUST NOT match a request that carries a query
    parameter the entry doesn't expect (e.g. `?page=2`). That is what
    distinguishes the first paginated call from later ones."""

    routes: list[tuple] = []

    def handler(request: httpx.Request) -> httpx.Response:
        full_url = str(request.url)
        path = request.url.path
        request_query_keys = set(dict(request.url.params).keys())
        # Pagination cursors that should bypass path-only routes.
        cursor_keys = {"page", "after", "before", "cursor"}
        for entry, status, body, headers in routes:
            if entry.startswith("http"):
                if full_url == entry:
                    return httpx.Response(status, json=body, headers=headers or {})
            elif path == entry and not (request_query_keys & cursor_keys):
                return httpx.Response(status, json=body, headers=headers or {})
        return httpx.Response(404, json={"message": "not found"})

    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)
    c = GitHubClient(settings, http=http)
    c._token = "TKN"  # bypass App auth
    c._routes = routes  # type: ignore[attr-defined]
    return c


def test_iter_repos_paginates(client: GitHubClient):
    page1_url = "/installation/repositories"
    page2_url = "https://api.github.com/installation/repositories?page=2"
    client._routes.append((  # type: ignore[attr-defined]
        page1_url,
        200,
        {"repositories": [_repo("a/one")]},
        {"Link": f'<{page2_url}>; rel="next"'},
    ))
    client._routes.append((  # type: ignore[attr-defined]
        page2_url,
        200,
        {"repositories": [_repo("a/two")]},
        {},
    ))
    repos = list(client.iter_repos())
    assert [r.full_name for r in repos] == ["a/one", "a/two"]


def test_iter_repos_only_filter(client: GitHubClient):
    client._routes.append((  # type: ignore[attr-defined]
        "/installation/repositories",
        200,
        {"repositories": [_repo("a/one"), _repo("a/two")]},
        {},
    ))
    repos = list(client.iter_repos(only="a/two"))
    assert [r.full_name for r in repos] == ["a/two"]


def test_fetch_workflows_returns_empty_on_404(client: GitHubClient):
    repo = _to_view("a/none")
    # No route matches => 404 => empty dict
    assert client.fetch_workflows(repo) == {}


def test_fetch_workflows_decodes_base64(client: GitHubClient):
    yaml_text = "on: push\njobs: {}\n"
    encoded = base64.b64encode(yaml_text.encode("utf-8")).decode("ascii")
    client._routes.append((  # type: ignore[attr-defined]
        "/repos/a/b/contents/.github/workflows",
        200,
        [{"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml"}],
        {},
    ))
    client._routes.append((  # type: ignore[attr-defined]
        "/repos/a/b/contents/.github/workflows/ci.yml",
        200,
        {"content": encoded},
        {},
    ))
    out = client.fetch_workflows(_to_view("a/b"))
    assert out == {".github/workflows/ci.yml": yaml_text}


def test_fetch_branch_protection_404_returns_none(client: GitHubClient):
    assert client.fetch_branch_protection(_to_view("a/b")) is None


def test_fetch_dependabot_alerts_403_returns_empty(client: GitHubClient):
    client._routes.append((  # type: ignore[attr-defined]
        "/repos/a/b/dependabot/alerts",
        403,
        {"message": "Dependabot disabled"},
        {},
    ))
    assert list(client.fetch_dependabot_alerts(_to_view("a/b"))) == []


def test_fetch_suppression_fingerprints_extracts_sha256(client: GitHubClient):
    fp = "a" * 64
    client._routes.append((  # type: ignore[attr-defined]
        "/repos/a/b/issues",
        200,
        [
            {"body": f"Suppress this. fingerprint: {fp}"},
            {"body": "no fingerprint here"},
            {"body": None},
        ],
        {},
    ))
    fps = client.fetch_suppression_fingerprints(_to_view("a/b"))
    assert fps == {fp}


def test_clone_url_bakes_token(client: GitHubClient):
    url = client.clone_url(_to_view("a/b"))
    assert "x-access-token:TKN@github.com/a/b.git" in url


def test_next_link_parses_rel_next():
    header = (
        '<https://api.github.com/x?page=2>; rel="next", '
        '<https://api.github.com/x?page=5>; rel="last"'
    )
    assert _next_link(header) == "https://api.github.com/x?page=2"
    assert _next_link(None) is None
    assert _next_link('<x>; rel="prev"') is None


# --- helpers ---------------------------------------------------------------

def _repo(full_name: str) -> dict:
    return {
        "full_name": full_name,
        "default_branch": "main",
        "fork": False,
        "archived": False,
        "private": True,
        "permissions": {"push": True},
        "description": None,
        "topics": [],
        "clone_url": f"https://github.com/{full_name}.git",
        "pushed_at": "2026-05-01T00:00:00Z",
    }


def _to_view(full_name: str):
    from secwatcher.github_client import GitHubClient as _GC
    return _GC._to_view(_repo(full_name))
