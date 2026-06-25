from __future__ import annotations

import argparse
import time

from uri_punisher.abuseipdb import AbuseIPDBClient
from uri_punisher.mastodon import MastodonClient
from uri_punisher.service import PunisherService
from uri_punisher.settings import Settings
from uri_punisher.state import StateStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uri-punisher")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process queued work and one local-account poll, then exit.",
    )
    parser.add_argument(
        "--retry-failed-silences",
        action="store_true",
        help="Retry account silence actions recorded as failed, then exit.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = Settings.from_env()
    mastodon = MastodonClient.create(
        base_url=settings.mastodon_base_url,
        access_token=settings.mastodon_access_token,
        fallback_retry_seconds=settings.fallback_retry_seconds,
    )
    abuseipdb = AbuseIPDBClient.create(api_key=settings.abuseipdb_api_key)
    state = StateStore(settings.state_dir)
    service = PunisherService(
        mastodon=mastodon,
        abuseipdb=abuseipdb,
        state=state,
        admin_accounts=settings.admin_accounts,
        fallback_retry_seconds=settings.fallback_retry_seconds,
    )

    if args.retry_failed_silences:
        service.retry_failed_account_silences()
        return

    while True:
        service.poll_once()
        if args.once:
            return
        time.sleep(settings.poll_interval_seconds)
