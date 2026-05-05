"""App-authenticated GitHub REST client with rate-limit awareness.

Single chokepoint (`_request`) updates `RateLimitState` from response headers
and sleeps when headroom is low. Callers receive parsed JSON or paginated
iterators. The installation token is refreshed on 401 once.
"""

from __future__ import annotations

import base64
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from secwatcher.auth import GITHUB_API, GitHubAppAuth
from secwatcher.config import Settings
from secwatcher.rate_limiter import RateLimitState, sleep_if_low
from secwatcher.suppression import SuppressionRules

logger = logging.getLogger(__name__)

FINGERPRINT_RE = re.compile(r"fingerprint:\s*([a-f0-9]{64})", re.IGNORECASE)


@dataclass
class RepoView:
    """Concrete `Repository` shape, populated from `/installation/repositories`."""

    full_name: str
    default_branch: str
    fork: bool
    archived: bool
    private: bool
    has_push_access: bool
    description: str | None
    topics: list[str]
    clone_url: str
    pushed_at: datetime


class GitHubClient:
    """Thin App-authed REST client. One instance per scan run."""

    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self._auth = GitHubAppAuth(
            app_id=settings.app_id,
            installation_id=settings.installation_id,
            private_key=settings.private_key,
        )
        self._http = http or httpx.Client(timeout=30.0)
        self._token: str | None = None

    # ---- public surface ---------------------------------------------------

    def iter_repos(self, *, only: str | None = None) -> Iterator[RepoView]:
        """Paginate /installation/repositories. `only` filters to one full_name."""
        for page in self._paginate("/installation/repositories", key="repositories"):
            for raw in page:
                if only and raw["full_name"] != only:
                    continue
                yield self._to_view(raw)

    def fetch_workflows(self, repo: RepoView) -> dict[str, str]:
        """Returns {path: yaml_text} for every .github/workflows/*.yml file."""
        try:
            listing = self._request(
                "GET", f"/repos/{repo.full_name}/contents/.github/workflows"
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {}
            raise
        out: dict[str, str] = {}
        for entry in listing.json():
            if entry.get("type") != "file":
                continue
            name = entry["name"]
            if not (name.endswith(".yml") or name.endswith(".yaml")):
                continue
            content = self._request(
                "GET", f"/repos/{repo.full_name}/contents/{entry['path']}"
            ).json()
            text = base64.b64decode(content["content"]).decode("utf-8", errors="replace")
            out[entry["path"]] = text
        return out

    def fetch_branch_protection(self, repo: RepoView) -> dict[str, Any] | None:
        try:
            resp = self._request(
                "GET",
                f"/repos/{repo.full_name}/branches/{repo.default_branch}/protection",
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise
        return resp.json()

    def fetch_dependabot_alerts(self, repo: RepoView) -> Iterator[dict[str, Any]]:
        """Open CRITICAL+HIGH alerts. Returns empty iter when Dependabot is off."""
        params = {"state": "open", "severity": "critical,high", "per_page": "100"}
        try:
            for page in self._paginate(
                f"/repos/{repo.full_name}/dependabot/alerts", params=params
            ):
                yield from page
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                return
            raise

    def fetch_scanner_ignore(self, repo: RepoView) -> SuppressionRules:
        try:
            resp = self._request(
                "GET", f"/repos/{repo.full_name}/contents/.scanner-ignore"
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return SuppressionRules()
            raise
        body = resp.json()
        text = base64.b64decode(body["content"]).decode("utf-8", errors="replace")
        return SuppressionRules.from_yaml(text)

    def fetch_suppression_fingerprints(self, repo: RepoView) -> set[str]:
        params = {"labels": "scanner:suppressed", "state": "open", "per_page": "100"}
        fingerprints: set[str] = set()
        try:
            for page in self._paginate(
                f"/repos/{repo.full_name}/issues", params=params
            ):
                for issue in page:
                    body = issue.get("body") or ""
                    fingerprints.update(FINGERPRINT_RE.findall(body))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 410):
                return fingerprints
            raise
        return fingerprints

    def clone_url(self, repo: RepoView) -> str:
        token = self._installation_token()
        return f"https://x-access-token:{token}@github.com/{repo.full_name}.git"

    # ---- internals --------------------------------------------------------

    def _installation_token(self) -> str:
        if self._token is None:
            self._token = self._auth.installation_token()
        return self._token

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        retry_on_unauthorized: bool = True,
    ) -> httpx.Response:
        url = path if path.startswith("http") else f"{GITHUB_API}{path}"
        headers = {
            "Authorization": f"Bearer {self._installation_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "secwatcher/0.1",
        }
        # httpx replaces an existing query string when params is a dict
        # (even an empty one). For pagination, the next-page URL already
        # contains the cursor query, so pass params only when truthy.
        request_kwargs: dict = {"headers": headers}
        if params:
            request_kwargs["params"] = params
        resp = self._http.request(method, url, **request_kwargs)
        if resp.status_code == 401 and retry_on_unauthorized:
            logger.info("401 from GitHub; refreshing installation token and retrying.")
            self._token = self._auth.installation_token()
            return self._request(
                method, path, params=params, retry_on_unauthorized=False
            )
        sleep_if_low(RateLimitState.from_headers(resp.headers))
        resp.raise_for_status()
        return resp

    def _paginate(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        key: str | None = None,
    ) -> Iterator[list[dict[str, Any]]]:
        """Yields successive pages as lists. `key` extracts a nested array (e.g.
        `/installation/repositories` returns `{repositories: [...]}`)."""
        next_url: str | None = path
        next_params = dict(params or {})
        next_params.setdefault("per_page", "100")
        while next_url:
            resp = self._request("GET", next_url, params=next_params)
            data = resp.json()
            page = data[key] if key else data
            yield page
            next_params = {}  # subsequent pages carry params in the Link URL
            next_url = _next_link(resp.headers.get("link"))

    @staticmethod
    def _to_view(raw: dict[str, Any]) -> RepoView:
        permissions = raw.get("permissions") or {}
        pushed_raw = raw.get("pushed_at") or raw.get("updated_at")
        pushed_at = (
            datetime.fromisoformat(pushed_raw.replace("Z", "+00:00"))
            if pushed_raw
            else datetime.now(UTC)
        )
        return RepoView(
            full_name=raw["full_name"],
            default_branch=raw.get("default_branch") or "main",
            fork=bool(raw.get("fork", False)),
            archived=bool(raw.get("archived", False)),
            private=bool(raw.get("private", False)),
            has_push_access=bool(permissions.get("push", False)),
            description=raw.get("description"),
            topics=list(raw.get("topics") or []),
            clone_url=raw.get("clone_url") or f"https://github.com/{raw['full_name']}.git",
            pushed_at=pushed_at,
        )


def _next_link(header: str | None) -> str | None:
    """Parse RFC 5988 Link header for rel=next."""
    if not header:
        return None
    for part in header.split(","):
        chunk = part.strip()
        if 'rel="next"' in chunk:
            start = chunk.find("<")
            end = chunk.find(">")
            if start != -1 and end != -1:
                return chunk[start + 1 : end]
    return None
