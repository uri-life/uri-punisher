from __future__ import annotations

import email.utils
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


class MastodonAPIError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class RateLimitedError(MastodonAPIError):
    def __init__(self, retry_at: datetime) -> None:
        super().__init__("Mastodon API rate limit exceeded", status_code=429)
        self.retry_at = retry_at


def parse_retry_at(
    headers: httpx.Headers | dict[str, str],
    *,
    now: datetime | None = None,
    fallback_seconds: int = 300,
) -> datetime:
    now = now or datetime.now(UTC)
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            return now + timedelta(seconds=max(0, int(retry_after)))
        except ValueError:
            parsed = email.utils.parsedate_to_datetime(retry_after)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)

    reset = headers.get("X-RateLimit-Reset")
    if reset:
        try:
            parsed = datetime.fromisoformat(reset.replace("Z", "+00:00"))
        except ValueError:
            parsed = email.utils.parsedate_to_datetime(reset)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    return now + timedelta(seconds=fallback_seconds)


@dataclass
class MastodonClient:
    http: httpx.Client
    fallback_retry_seconds: int = 300

    @classmethod
    def create(
        cls,
        *,
        base_url: str,
        access_token: str,
        timeout: float = 20.0,
        fallback_retry_seconds: int = 300,
    ) -> MastodonClient:
        return cls(
            http=httpx.Client(
                base_url=base_url.rstrip("/"),
                timeout=timeout,
                headers={"Authorization": f"Bearer {access_token}"},
            ),
            fallback_retry_seconds=fallback_retry_seconds,
        )

    def list_local_accounts(self, since_id: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, str] | None = {"origin": "local", "limit": "200"}
        if since_id:
            params["since_id"] = since_id
        url = "/api/v2/admin/accounts"
        accounts: list[dict[str, Any]] = []
        while True:
            kwargs = {"params": params} if params is not None else {}
            response = self._request("GET", url, **kwargs)
            accounts.extend(self._json(response))
            next_url = response.links.get("next", {}).get("url")
            if not next_url:
                return accounts
            url = next_url
            params = None

    def list_mention_notifications(
        self, since_id: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, str | list[str]] | None = {
            "types[]": ["mention"],
            "limit": "80",
        }
        if since_id:
            params["min_id"] = since_id
        url = "/api/v1/notifications"
        notifications: list[dict[str, Any]] = []
        while True:
            kwargs = {"params": params} if params is not None else {}
            response = self._request("GET", url, **kwargs)
            notifications.extend(self._json(response))
            newer_url = response.links.get("prev", {}).get("url")
            if not since_id or not newer_url:
                return notifications
            url = newer_url
            params = None

    def find_local_account(self, username: str) -> dict[str, Any] | None:
        response = self._request(
            "GET",
            "/api/v1/admin/accounts",
            params={
                "local": "true",
                "username": username,
                "limit": "100",
            },
        )
        accounts = self._json(response)
        for account in accounts:
            if account.get("domain") is None and account.get("username") == username:
                return account
        return None

    def find_ip_block(self, ip_cidr: str) -> dict[str, Any] | None:
        params: dict[str, str] | None = {"limit": "200"}
        url = "/api/v1/admin/ip_blocks"
        while True:
            kwargs = {"params": params} if params is not None else {}
            response = self._request("GET", url, **kwargs)
            for block in self._json(response):
                if block.get("ip") == ip_cidr or block.get("ip_cidr") == ip_cidr:
                    return block
            next_url = response.links.get("next", {}).get("url")
            if not next_url:
                return None
            url = next_url
            params = None

    def block_ip(
        self,
        *,
        ip_cidr: str,
        severity: str,
        comment: str,
        expires_in: int,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/api/v1/admin/ip_blocks",
            data={
                "ip": ip_cidr,
                "severity": severity,
                "comment": comment,
                "expires_in": str(expires_in),
            },
        )
        return self._json(response)

    def silence_account(
        self,
        *,
        account_id: str,
        text: str,
        send_email_notification: bool = True,
    ) -> None:
        response = self._request(
            "POST",
            f"/api/v1/admin/accounts/{account_id}/action",
            data={
                "type": "silence",
                "text": text,
                "send_email_notification": str(send_email_notification).lower(),
            },
        )
        self._raise_for_status(response)

    def _json(self, response: httpx.Response) -> Any:
        self._raise_for_status(response)
        return response.json()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            return self.http.request(method, path, **kwargs)
        except httpx.TransportError as error:
            raise MastodonAPIError(f"Mastodon API request failed: {error}") from error

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code == 429:
            raise RateLimitedError(
                parse_retry_at(
                    response.headers,
                    fallback_seconds=self.fallback_retry_seconds,
                )
            )
        if response.status_code >= 400:
            detail = response.text.strip()
            suffix = f": {detail}" if detail else ""
            raise MastodonAPIError(
                f"Mastodon API request failed: HTTP {response.status_code}{suffix}",
                status_code=response.status_code,
            )
