from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from uri_punisher.mastodon import MastodonAPIError, RateLimitedError
from uri_punisher.parsing import parse_bare_usernames
from uri_punisher.policy import (
    AccountSilenceTextSource,
    account_silence_text,
    ip_action_for_score,
    ip_block_comment,
    should_silence_account,
    single_ip_cidr,
)
from uri_punisher.state import QueueJob, StateStore


class MastodonAPI(Protocol):
    def list_mention_notifications(
        self, since_id: str | None = None
    ) -> list[dict[str, Any]]: ...

    def list_local_accounts(
        self, since_id: str | None = None
    ) -> list[dict[str, Any]]: ...

    def find_local_account(self, username: str) -> dict[str, Any] | None: ...

    def find_ip_block(self, ip_cidr: str) -> dict[str, Any] | None: ...

    def block_ip(
        self,
        *,
        ip_cidr: str,
        severity: str,
        comment: str,
        expires_in: int,
    ) -> dict[str, Any]: ...

    def silence_account(
        self,
        *,
        account_id: str,
        text: str,
        send_email_notification: bool = True,
    ) -> None: ...


class AbuseIPDBAPI(Protocol):
    def check_ip(self, ip: str) -> int: ...


@dataclass
class ActionContext:
    scores: dict[str, int] = field(default_factory=dict)
    handled_ip_cidrs: set[str] = field(default_factory=set)
    silenced_account_ids: set[str] = field(default_factory=set)


@dataclass
class PunisherService:
    mastodon: MastodonAPI
    abuseipdb: AbuseIPDBAPI
    state: StateStore
    admin_accounts: set[str]
    fallback_retry_seconds: int = 300

    def poll_once(self) -> None:
        self.process_due_queue()
        self.process_mention_notifications()
        self.process_local_accounts()

    def retry_failed_account_silences(self) -> None:
        text = account_silence_text("", 0, source="login")
        for account_id in self.state.failed_account_silence_ids():
            self.state.enqueue_job(
                QueueJob.create(
                    kind="account_silence",
                    payload={"account_id": account_id, "text": text},
                    run_after=datetime.now(UTC),
                )
            )
        self.process_due_queue()

    def process_mention_notifications(self) -> None:
        state = self.state.load_state()
        notification_cursor = state.get("notification_cursor")
        notifications = self.mastodon.list_mention_notifications(
            since_id=notification_cursor
        )
        if not notifications:
            return

        newest_id = max(
            (str(notification["id"]) for notification in notifications), key=int
        )
        if not notification_cursor:
            self.state.update_state({"notification_cursor": newest_id})
            return

        context = ActionContext()
        for notification in sorted(notifications, key=lambda item: int(item["id"])):
            self.process_dm_notification(notification, context)
        self.state.update_state({"notification_cursor": newest_id})

    def process_local_accounts(self) -> None:
        state = self.state.load_state()
        account_cursor = state.get("account_cursor")
        accounts = self.mastodon.list_local_accounts(since_id=account_cursor)
        if not accounts:
            return

        newest_id = max((str(account["id"]) for account in accounts), key=int)
        if not account_cursor:
            self.state.update_state({"account_cursor": newest_id})
            return

        context = ActionContext()
        processed_account_ids = _processed_account_ids(state)
        for account in sorted(accounts, key=lambda item: int(item["id"])):
            account_id = str(account.get("id", ""))
            if not account_id or account_id in processed_account_ids:
                continue
            self.process_account(account, context, silence_text_source="signup")
            processed_account_ids.add(account_id)
        self.state.update_state(
            {
                "account_cursor": newest_id,
                "processed_account_ids": sorted(processed_account_ids, key=int),
            }
        )

    def process_due_queue(self) -> None:
        for job in self.state.due_jobs():
            try:
                if job.kind == "ip_block":
                    self._perform_ip_block(**job.payload)
                elif job.kind == "account_silence":
                    self._perform_account_silence(**job.payload)
                else:
                    self.state.record_event("unknown_job_kind", job.to_json())
                    self.state.complete_job(job.id)
                    continue
            except RateLimitedError as error:
                self.state.reschedule_job(job.id, error.retry_at)
            except MastodonAPIError as error:
                if job.kind == "account_silence":
                    self.state.record_event(
                        "account_silence_retry_blocked",
                        {"job": job.to_json(), "error": str(error)},
                    )
                    self.state.reschedule_job(job.id, self._fallback_retry_at())
                    continue
                if is_retryable_mastodon_error(error):
                    self.state.reschedule_job(job.id, self._fallback_retry_at())
                    continue
                self.state.record_event(
                    "mastodon_job_failed",
                    {"job": job.to_json(), "error": str(error)},
                )
                self.state.complete_job(job.id)
            else:
                self.state.complete_job(job.id)

    def process_dm_notification(
        self,
        notification: dict[str, Any],
        context: ActionContext | None = None,
    ) -> None:
        context = context or ActionContext()
        account = notification.get("account") or {}
        sender_candidates = {account.get("acct"), account.get("username")}
        if not (sender_candidates & self.admin_accounts):
            return

        status = notification.get("status") or {}
        if status.get("visibility") not in {None, "direct"}:
            return

        for username in parse_bare_usernames(status.get("content", "")):
            account = self.mastodon.find_local_account(username)
            if account:
                self.process_account(
                    account,
                    context,
                    silence_text_source="login",
                )
                self._record_processed_account(account)

    def process_account(
        self,
        account: dict[str, Any],
        context: ActionContext | None = None,
        *,
        silence_text_source: AccountSilenceTextSource = "signup",
    ) -> None:
        context = context or ActionContext()
        ip = latest_account_ip(account)
        if not ip:
            return

        score = self._score(ip, context)
        self._apply_ip_policy(ip, score, context)
        self._apply_account_policy(
            account,
            ip,
            score,
            context,
            silence_text_source=silence_text_source,
        )

    def _score(self, ip: str, context: ActionContext) -> int:
        if ip not in context.scores:
            context.scores[ip] = self.abuseipdb.check_ip(ip)
        return context.scores[ip]

    def _apply_ip_policy(self, ip: str, score: int, context: ActionContext) -> None:
        action = ip_action_for_score(score)
        if not action:
            return
        ip_cidr = single_ip_cidr(ip)
        if ip_cidr in context.handled_ip_cidrs:
            return
        context.handled_ip_cidrs.add(ip_cidr)
        try:
            self._perform_ip_block(
                ip=ip,
                score=score,
                severity=action.severity,
                expires_in=action.expires_in,
            )
        except RateLimitedError as error:
            self.state.enqueue_job(
                QueueJob.create(
                    kind="ip_block",
                    payload={
                        "ip": ip,
                        "score": score,
                        "severity": action.severity,
                        "expires_in": action.expires_in,
                    },
                    run_after=error.retry_at,
                )
            )
        except MastodonAPIError as error:
            if not is_retryable_mastodon_error(error):
                raise
            self.state.enqueue_job(
                QueueJob.create(
                    kind="ip_block",
                    payload={
                        "ip": ip,
                        "score": score,
                        "severity": action.severity,
                        "expires_in": action.expires_in,
                    },
                    run_after=self._fallback_retry_at(),
                )
            )

    def _apply_account_policy(
        self,
        account: dict[str, Any],
        ip: str,
        score: int,
        context: ActionContext,
        *,
        silence_text_source: AccountSilenceTextSource,
    ) -> None:
        account_id = str(account.get("id", ""))
        if (
            not account_id
            or account.get("silenced")
            or not should_silence_account(score)
        ):
            return
        if account_id in context.silenced_account_ids:
            return
        context.silenced_account_ids.add(account_id)
        text = account_silence_text(ip, score, source=silence_text_source)
        try:
            self._perform_account_silence(account_id=account_id, text=text)
        except RateLimitedError as error:
            self.state.enqueue_job(
                QueueJob.create(
                    kind="account_silence",
                    payload={"account_id": account_id, "text": text},
                    run_after=error.retry_at,
                )
            )
        except MastodonAPIError as error:
            if not is_retryable_mastodon_error(error):
                job = QueueJob.create(
                    kind="account_silence",
                    payload={"account_id": account_id, "text": text},
                    run_after=self._fallback_retry_at(),
                )
                self.state.enqueue_job(job)
                self.state.record_event(
                    "account_silence_retry_queued",
                    {"job": job.to_json(), "error": str(error)},
                )
                return
            self.state.enqueue_job(
                QueueJob.create(
                    kind="account_silence",
                    payload={"account_id": account_id, "text": text},
                    run_after=self._fallback_retry_at(),
                )
            )

    def _perform_ip_block(
        self,
        *,
        ip: str,
        score: int,
        severity: str,
        expires_in: int,
    ) -> None:
        ip_cidr = single_ip_cidr(ip)
        if self.mastodon.find_ip_block(ip_cidr):
            return
        self.mastodon.block_ip(
            ip_cidr=ip_cidr,
            severity=severity,
            comment=ip_block_comment(ip, score),
            expires_in=expires_in,
        )

    def _perform_account_silence(self, *, account_id: str, text: str) -> None:
        self.mastodon.silence_account(
            account_id=account_id,
            text=text,
            send_email_notification=True,
        )

    def _fallback_retry_at(self) -> datetime:
        return datetime.now(UTC) + timedelta(seconds=self.fallback_retry_seconds)

    def _record_processed_account(self, account: dict[str, Any]) -> None:
        account_id = str(account.get("id", ""))
        if not account_id:
            return
        state = self.state.load_state()
        processed_account_ids = _processed_account_ids(state)
        processed_account_ids.add(account_id)
        self.state.update_state(
            {"processed_account_ids": sorted(processed_account_ids, key=int)}
        )


def latest_account_ip(account: dict[str, Any]) -> str | None:
    ips = account.get("ips") or []
    if ips:
        sorted_ips = sorted(
            ips,
            key=lambda item: _parse_datetime(item.get("used_at")),
            reverse=True,
        )
        ip = sorted_ips[0].get("ip")
        if ip:
            return str(ip)
    ip = account.get("ip")
    return str(ip) if ip else None


def _processed_account_ids(state: dict[str, Any]) -> set[str]:
    return {str(account_id) for account_id in state.get("processed_account_ids", [])}


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def is_retryable_mastodon_error(error: MastodonAPIError) -> bool:
    return error.status_code is None or error.status_code >= 500
