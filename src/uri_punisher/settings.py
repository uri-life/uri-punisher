from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    mastodon_base_url: str
    mastodon_access_token: str
    abuseipdb_api_key: str
    state_dir: Path
    admin_accounts: set[str]
    poll_interval_seconds: float = 30.0
    fallback_retry_seconds: int = 300

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv(dotenv_path=Path(".env"), override=False)
        return cls(
            mastodon_base_url=_required("MASTODON_BASE_URL"),
            mastodon_access_token=_required("MASTODON_ACCESS_TOKEN"),
            abuseipdb_api_key=_required("ABUSEIPDB_API_KEY"),
            state_dir=Path(_required("STATE_DIR")),
            admin_accounts=_required_set("ADMIN_ACCOUNTS"),
            poll_interval_seconds=float(os.environ.get("POLL_INTERVAL_SECONDS", "30")),
            fallback_retry_seconds=int(os.environ.get("FALLBACK_RETRY_SECONDS", "300")),
        )


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _split_set(value: str) -> set[str]:
    return {part.strip() for part in value.replace(",", " ").split() if part.strip()}


def _required_set(name: str) -> set[str]:
    values = _split_set(_required(name))
    if not values:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return values
