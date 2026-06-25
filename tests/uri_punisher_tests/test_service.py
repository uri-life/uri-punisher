from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from uri_punisher.mastodon import MastodonAPIError, RateLimitedError
from uri_punisher.service import ActionContext, PunisherService, latest_account_ip
from uri_punisher.state import QueueJob, StateStore


@dataclass
class FakeAbuseIPDB:
    scores: dict[str, int]
    checks: list[str] = field(default_factory=list)

    def check_ip(self, ip: str) -> int:
        self.checks.append(ip)
        return self.scores[ip]


@dataclass
class FakeMastodon:
    local_accounts: list[dict[str, Any]] = field(default_factory=list)
    mention_notifications: list[dict[str, Any]] = field(default_factory=list)
    accounts_by_username: dict[str, dict[str, Any]] = field(default_factory=dict)
    ip_blocks_by_cidr: dict[str, dict[str, Any]] = field(default_factory=dict)
    list_account_since_ids: list[str | None] = field(default_factory=list)
    list_notification_since_ids: list[str | None] = field(default_factory=list)
    blocks: list[dict[str, Any]] = field(default_factory=list)
    silences: list[dict[str, Any]] = field(default_factory=list)
    block_rate_limit_until: datetime | None = None
    block_error: MastodonAPIError | None = None
    silence_error: MastodonAPIError | None = None

    def list_mention_notifications(
        self, since_id: str | None = None
    ) -> list[dict[str, Any]]:
        self.list_notification_since_ids.append(since_id)
        if since_id is None:
            return self.mention_notifications
        return [
            notification
            for notification in self.mention_notifications
            if int(notification["id"]) > int(since_id)
        ]

    def list_local_accounts(self, since_id: str | None = None) -> list[dict[str, Any]]:
        self.list_account_since_ids.append(since_id)
        if since_id is None:
            return self.local_accounts
        return [
            account
            for account in self.local_accounts
            if int(account["id"]) > int(since_id)
        ]

    def find_local_account(self, username: str) -> dict[str, Any] | None:
        return self.accounts_by_username.get(username)

    def find_ip_block(self, ip_cidr: str) -> dict[str, Any] | None:
        return self.ip_blocks_by_cidr.get(ip_cidr)

    def block_ip(
        self,
        *,
        ip_cidr: str,
        severity: str,
        comment: str,
        expires_in: int,
    ) -> dict[str, Any]:
        if self.block_rate_limit_until:
            raise RateLimitedError(self.block_rate_limit_until)
        if self.block_error:
            raise self.block_error
        block = {
            "ip_cidr": ip_cidr,
            "severity": severity,
            "comment": comment,
            "expires_in": expires_in,
        }
        self.blocks.append(block)
        return block

    def silence_account(
        self,
        *,
        account_id: str,
        text: str,
        send_email_notification: bool = True,
    ) -> None:
        if self.silence_error:
            raise self.silence_error
        self.silences.append(
            {
                "account_id": account_id,
                "text": text,
                "send_email_notification": send_email_notification,
            }
        )


def build_service(
    tmp_path: Any, mastodon: FakeMastodon, abuse: FakeAbuseIPDB
) -> PunisherService:
    return PunisherService(
        mastodon=mastodon,
        abuseipdb=abuse,
        state=StateStore(tmp_path),
        admin_accounts={"admin"},
    )


def account(
    account_id: str,
    username: str,
    ip: str,
    *,
    silenced: bool = False,
) -> dict[str, Any]:
    return {
        "id": account_id,
        "username": username,
        "domain": None,
        "ip": ip,
        "silenced": silenced,
    }


def mention_notification(
    notification_id: str,
    *,
    sender_username: str = "admin",
    visibility: str = "direct",
    content: str = "alice",
) -> dict[str, Any]:
    return {
        "id": notification_id,
        "type": "mention",
        "account": {"username": sender_username, "acct": sender_username},
        "status": {"visibility": visibility, "content": content},
    }


def test_process_account_blocks_single_ip_and_silences_for_80_or_above(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon()
    abuse = FakeAbuseIPDB({"203.0.113.9": 80})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_account(account("1", "alice", "203.0.113.9"))

    assert mastodon.blocks == [
        {
            "ip_cidr": "203.0.113.9/32",
            "severity": "no_access",
            "comment": (
                "Automated single-IP action: AbuseIPDB abuse confidence score 80. "
                "Evidence: https://www.abuseipdb.com/check/203.0.113.9"
            ),
            "expires_in": 30 * 24 * 60 * 60,
        }
    ]
    assert mastodon.silences[0]["account_id"] == "1"
    assert mastodon.silences[0]["send_email_notification"] is True
    assert "악용 행위" in mastodon.silences[0]["text"]
    assert "이 계정을 만들 때" in mastodon.silences[0]["text"]
    assert "로그인할 때" not in mastodon.silences[0]["text"]
    assert "https://" not in mastodon.silences[0]["text"]


def test_process_account_does_not_silence_for_50_60_70_scores(tmp_path: Any) -> None:
    for score in (50, 60, 70):
        mastodon = FakeMastodon()
        abuse = FakeAbuseIPDB({"203.0.113.9": score})
        service = build_service(tmp_path / str(score), mastodon, abuse)

        service.process_account(account("1", "alice", "203.0.113.9"))

        assert mastodon.blocks
        assert mastodon.silences == []


def test_process_account_skips_existing_ip_block_and_still_silences(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(ip_blocks_by_cidr={"203.0.113.9/32": {"id": "existing"}})
    abuse = FakeAbuseIPDB({"203.0.113.9": 80})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_account(account("1", "alice", "203.0.113.9"))

    assert mastodon.blocks == []
    assert mastodon.silences[0]["account_id"] == "1"


def test_latest_account_ip_uses_most_recent_used_at() -> None:
    assert (
        latest_account_ip(
            {
                "ip": "203.0.113.1",
                "ips": [
                    {"ip": "203.0.113.2", "used_at": "2026-06-24T00:00:00Z"},
                    {"ip": "203.0.113.3", "used_at": "2026-06-25T00:00:00Z"},
                ],
            }
        )
        == "203.0.113.3"
    )


def test_dm_processing_deduplicates_shared_ip_within_one_message(tmp_path: Any) -> None:
    shared_ip = "203.0.113.10"
    mastodon = FakeMastodon(
        accounts_by_username={
            "alice": account("1", "alice", shared_ip),
            "bob": account("2", "bob", shared_ip),
        }
    )
    abuse = FakeAbuseIPDB({shared_ip: 90})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_dm_notification(
        {
            "type": "mention",
            "account": {"username": "admin", "acct": "admin"},
            "status": {"visibility": "direct", "content": "alice bob"},
        },
        ActionContext(),
    )

    assert abuse.checks == [shared_ip]
    assert len(mastodon.blocks) == 1
    assert len(mastodon.silences) == 2
    assert all("이 계정에 로그인할 때" in item["text"] for item in mastodon.silences)
    assert all("이 계정을 만들 때" not in item["text"] for item in mastodon.silences)
    assert service.state.load_state()["processed_account_ids"] == ["1", "2"]


def test_first_poll_bootstraps_without_processing_existing_accounts(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(local_accounts=[account("1", "alice", "203.0.113.9")])
    abuse = FakeAbuseIPDB({"203.0.113.9": 100})
    service = build_service(tmp_path, mastodon, abuse)

    service.poll_once()

    assert mastodon.blocks == []
    assert mastodon.silences == []
    state = service.state.load_state()
    assert state["account_cursor"] == "1"
    assert "bootstrapped" not in state
    assert "notification_cursor" not in state


def test_first_notification_poll_bootstraps_without_processing_existing_notifications(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(
        mention_notifications=[mention_notification("10")],
        accounts_by_username={"alice": account("1", "alice", "203.0.113.9")},
    )
    abuse = FakeAbuseIPDB({"203.0.113.9": 100})
    service = build_service(tmp_path, mastodon, abuse)

    service.poll_once()

    assert mastodon.blocks == []
    assert mastodon.silences == []
    assert mastodon.list_notification_since_ids == [None]
    assert service.state.load_state()["notification_cursor"] == "10"


def test_poll_processes_direct_mention_notifications_after_bootstrap(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(
        mention_notifications=[mention_notification("11", content="alice")],
        accounts_by_username={"alice": account("1", "alice", "203.0.113.9")},
    )
    abuse = FakeAbuseIPDB({"203.0.113.9": 90})
    service = build_service(tmp_path, mastodon, abuse)
    service.state.update_state({"notification_cursor": "10"})

    service.poll_once()

    assert mastodon.list_notification_since_ids == ["10"]
    assert abuse.checks == ["203.0.113.9"]
    assert mastodon.blocks[0]["ip_cidr"] == "203.0.113.9/32"
    assert mastodon.silences[0]["account_id"] == "1"
    assert "이 계정에 로그인할 때" in mastodon.silences[0]["text"]
    assert service.state.load_state()["notification_cursor"] == "11"
    assert service.state.load_state()["processed_account_ids"] == ["1"]


def test_poll_ignores_non_command_mentions_but_advances_notification_cursor(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(
        mention_notifications=[
            mention_notification("11", sender_username="not_admin", content="alice"),
            mention_notification("12", visibility="public", content="alice"),
            mention_notification("13", content="@alice alice@example.test"),
        ],
        accounts_by_username={"alice": account("1", "alice", "203.0.113.9")},
    )
    abuse = FakeAbuseIPDB({"203.0.113.9": 90})
    service = build_service(tmp_path, mastodon, abuse)
    service.state.update_state({"notification_cursor": "10"})

    service.poll_once()

    assert abuse.checks == []
    assert mastodon.blocks == []
    assert mastodon.silences == []
    assert service.state.load_state()["notification_cursor"] == "13"


def test_notification_processed_account_is_not_reprocessed_by_local_account_poll(
    tmp_path: Any,
) -> None:
    bob = account("2", "bob", "203.0.113.10")
    mastodon = FakeMastodon(
        local_accounts=[bob],
        mention_notifications=[mention_notification("11", content="bob")],
        accounts_by_username={"bob": bob},
    )
    abuse = FakeAbuseIPDB({"203.0.113.10": 90})
    service = build_service(tmp_path, mastodon, abuse)
    service.state.update_state({"notification_cursor": "10", "account_cursor": "1"})

    service.poll_once()

    assert abuse.checks == ["203.0.113.10"]
    assert len(mastodon.blocks) == 1
    assert len(mastodon.silences) == 1
    assert service.state.load_state()["account_cursor"] == "2"
    assert service.state.load_state()["processed_account_ids"] == ["2"]


def test_poll_processes_new_accounts_after_bootstrap(tmp_path: Any) -> None:
    mastodon = FakeMastodon(local_accounts=[account("1", "alice", "203.0.113.9")])
    abuse = FakeAbuseIPDB({"203.0.113.10": 80})
    service = build_service(tmp_path, mastodon, abuse)

    service.poll_once()
    mastodon.local_accounts.append(account("2", "bob", "203.0.113.10"))
    service.poll_once()

    assert mastodon.list_account_since_ids == [None, "1"]
    assert mastodon.blocks[0]["ip_cidr"] == "203.0.113.10/32"
    assert mastodon.silences[0]["account_id"] == "2"
    assert "이 계정을 만들 때" in mastodon.silences[0]["text"]
    assert service.state.load_state()["account_cursor"] == "2"
    assert service.state.load_state()["processed_account_ids"] == ["2"]


def test_poll_processes_new_accounts_in_id_order_and_updates_cursor(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(
        local_accounts=[
            account("3", "carol", "203.0.113.13"),
            account("2", "bob", "203.0.113.12"),
        ]
    )
    abuse = FakeAbuseIPDB({"203.0.113.12": 80, "203.0.113.13": 90})
    service = build_service(tmp_path, mastodon, abuse)
    service.state.update_state({"account_cursor": "1"})

    service.poll_once()

    assert abuse.checks == ["203.0.113.12", "203.0.113.13"]
    assert [silence["account_id"] for silence in mastodon.silences] == ["2", "3"]
    assert service.state.load_state()["account_cursor"] == "3"
    assert service.state.load_state()["processed_account_ids"] == ["2", "3"]


def test_poll_skips_processed_accounts(tmp_path: Any) -> None:
    mastodon = FakeMastodon(
        local_accounts=[
            account("2", "bob", "203.0.113.12"),
            account("3", "carol", "203.0.113.13"),
        ]
    )
    abuse = FakeAbuseIPDB({"203.0.113.13": 80})
    service = build_service(tmp_path, mastodon, abuse)
    service.state.update_state({"account_cursor": "1", "processed_account_ids": ["2"]})

    service.poll_once()

    assert abuse.checks == ["203.0.113.13"]
    assert [silence["account_id"] for silence in mastodon.silences] == ["3"]
    assert service.state.load_state()["processed_account_ids"] == ["2", "3"]


def test_due_queue_recovers_after_restart(tmp_path: Any) -> None:
    state = StateStore(tmp_path)
    state.enqueue_job(
        QueueJob.create(
            kind="ip_block",
            payload={
                "ip": "203.0.113.12",
                "score": 100,
                "severity": "no_access",
                "expires_in": 180 * 24 * 60 * 60,
            },
            run_after=datetime.now(UTC) - timedelta(seconds=1),
        )
    )
    mastodon = FakeMastodon()
    service = PunisherService(
        mastodon=mastodon,
        abuseipdb=FakeAbuseIPDB({}),
        state=StateStore(tmp_path),
        admin_accounts={"admin"},
    )

    service.process_due_queue()

    assert mastodon.blocks[0]["ip_cidr"] == "203.0.113.12/32"
    assert StateStore(tmp_path).due_jobs() == []


def test_rate_limited_ip_block_is_persisted_for_retry(tmp_path: Any) -> None:
    retry_at = datetime.now(UTC) + timedelta(minutes=5)
    mastodon = FakeMastodon(block_rate_limit_until=retry_at)
    abuse = FakeAbuseIPDB({"203.0.113.13": 100})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_account(account("1", "alice", "203.0.113.13"))

    jobs = service.state.due_jobs(now=retry_at + timedelta(seconds=1))
    assert len(jobs) == 1
    assert jobs[0].kind == "ip_block"
    assert jobs[0].payload["ip"] == "203.0.113.13"


def test_retryable_mastodon_error_is_persisted_for_retry(tmp_path: Any) -> None:
    mastodon = FakeMastodon(
        block_error=MastodonAPIError("temporary failure", status_code=503)
    )
    abuse = FakeAbuseIPDB({"203.0.113.14": 100})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_account(account("1", "alice", "203.0.113.14"))

    jobs = service.state.due_jobs(now=datetime.now(UTC) + timedelta(minutes=10))
    assert len(jobs) == 1
    assert jobs[0].kind == "ip_block"
    assert jobs[0].payload["ip"] == "203.0.113.14"


def test_non_retryable_account_silence_error_is_queued_for_retry(
    tmp_path: Any,
) -> None:
    mastodon = FakeMastodon(
        silence_error=MastodonAPIError("This action is not allowed", status_code=403)
    )
    abuse = FakeAbuseIPDB({"203.0.113.14": 100})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_account(account("1", "alice", "203.0.113.14"))

    assert mastodon.blocks[0]["ip_cidr"] == "203.0.113.14/32"
    assert mastodon.silences == []
    jobs = service.state.due_jobs(now=datetime.now(UTC) + timedelta(minutes=10))
    assert len(jobs) == 1
    assert jobs[0].kind == "account_silence"
    assert jobs[0].payload["account_id"] == "1"
    events = (tmp_path / "queue_events.jsonl").read_text(encoding="utf-8")
    assert "account_silence_retry_queued" in events


def test_non_retryable_account_silence_queue_job_is_rescheduled(
    tmp_path: Any,
) -> None:
    state = StateStore(tmp_path)
    state.enqueue_job(
        QueueJob.create(
            kind="account_silence",
            payload={"account_id": "1", "text": "reason"},
            run_after=datetime.now(UTC) - timedelta(seconds=1),
        )
    )
    mastodon = FakeMastodon(
        silence_error=MastodonAPIError("This action is not allowed", status_code=403)
    )
    service = PunisherService(
        mastodon=mastodon,
        abuseipdb=FakeAbuseIPDB({}),
        state=state,
        admin_accounts={"admin"},
    )

    service.process_due_queue()

    jobs = state.due_jobs(now=datetime.now(UTC) + timedelta(minutes=10))
    assert len(jobs) == 1
    assert jobs[0].kind == "account_silence"
    assert jobs[0].attempts == 1
    events = (tmp_path / "queue_events.jsonl").read_text(encoding="utf-8")
    assert "account_silence_retry_blocked" in events


def test_retry_failed_account_silences_replays_recorded_failures(tmp_path: Any) -> None:
    state = StateStore(tmp_path)
    state.record_event(
        "account_silence_failed",
        {"account_id": "1", "error": "This action is not allowed"},
    )
    state.record_event(
        "account_silence_failed",
        {"account_id": "1", "error": "This action is not allowed"},
    )
    mastodon = FakeMastodon()
    service = PunisherService(
        mastodon=mastodon,
        abuseipdb=FakeAbuseIPDB({}),
        state=state,
        admin_accounts={"admin"},
    )

    service.retry_failed_account_silences()

    assert [silence["account_id"] for silence in mastodon.silences] == ["1"]
    assert state.due_jobs() == []


def test_regression_no_asn_or_range_actions_exist(tmp_path: Any) -> None:
    mastodon = FakeMastodon()
    abuse = FakeAbuseIPDB({"2001:db8::1": 100})
    service = build_service(tmp_path, mastodon, abuse)

    service.process_account(account("1", "alice", "2001:db8::1"))

    assert mastodon.blocks[0]["ip_cidr"] == "2001:db8::1/128"
    assert "asn" not in mastodon.blocks[0]
    assert "range" not in mastodon.blocks[0]
