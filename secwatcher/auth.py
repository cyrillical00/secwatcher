from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import jwt

GITHUB_API = "https://api.github.com"
TOKEN_TTL_SECONDS = 60 * 55  # GitHub installation tokens are valid for 60 min; refresh at 55.


@dataclass
class InstallationToken:
    token: str
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class GitHubAppAuth:
    """Mints JWTs for a GitHub App and exchanges them for installation tokens.

    Tokens are cached in memory and refreshed proactively before the 60-minute
    GitHub TTL elapses. Private key contents are never logged.
    """

    def __init__(self, app_id: str, installation_id: str, private_key: str) -> None:
        self._app_id = app_id
        self._installation_id = installation_id
        self._private_key = private_key
        self._cached: InstallationToken | None = None

    def _mint_jwt(self) -> str:
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self._app_id,
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def installation_token(self) -> str:
        if self._cached and not self._cached.expired:
            return self._cached.token

        app_jwt = self._mint_jwt()
        url = f"{GITHUB_API}/app/installations/{self._installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        resp = httpx.post(url, headers=headers, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        self._cached = InstallationToken(
            token=data["token"],
            expires_at=time.time() + TOKEN_TTL_SECONDS,
        )
        return self._cached.token
