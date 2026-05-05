from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    app_id: str
    installation_id: str
    private_key: str
    slack_webhook: str
    owner: str | None

    @classmethod
    def from_env(cls) -> Settings:
        missing: list[str] = []
        app_id = os.environ.get("REPOSENTRY_APP_ID", "")
        installation_id = os.environ.get("REPOSENTRY_INSTALLATION_ID", "")
        private_key = os.environ.get("REPOSENTRY_APP_PRIVATE_KEY", "")
        slack_webhook = os.environ.get("REPOSENTRY_SLACK_WEBHOOK", "")
        owner = os.environ.get("REPOSENTRY_OWNER") or None

        if not app_id:
            missing.append("REPOSENTRY_APP_ID")
        if not installation_id:
            missing.append("REPOSENTRY_INSTALLATION_ID")
        if not private_key:
            missing.append("REPOSENTRY_APP_PRIVATE_KEY")
        if not slack_webhook:
            missing.append("REPOSENTRY_SLACK_WEBHOOK")

        if missing:
            raise ConfigError(
                "Missing required environment variables: " + ", ".join(missing)
            )

        return cls(
            app_id=app_id,
            installation_id=installation_id,
            private_key=private_key,
            slack_webhook=slack_webhook,
            owner=owner,
        )
