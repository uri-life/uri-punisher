from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from uri_punisher.mastodon import (
    MastodonAPIError,
    MastodonClient,
    RateLimitedError,
    parse_retry_at,
)


def test_parse_retry_at_prefers_retry_after_seconds() -> None:
    now = datetime(2026, 6, 25, tzinfo=UTC)

    retry_at = parse_retry_at(
        {
            "Retry-After": "12",
            "X-RateLimit-Reset": "2026-06-26T00:00:00Z",
        },
        now=now,
    )

    assert retry_at == now + timedelta(seconds=12)


def test_parse_retry_at_uses_rate_limit_reset_without_retry_after() -> None:
    retry_at = parse_retry_at({"X-RateLimit-Reset": "2026-06-26T00:00:00Z"})

    assert retry_at == datetime(2026, 6, 26, tzinfo=UTC)


def test_block_ip_posts_single_ip_block_form_data() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": "1"})

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    client.block_ip(
        ip_cidr="203.0.113.4/32",
        severity="sign_up_block",
        comment="comment",
        expires_in=259200,
    )

    request = requests[0]
    assert request.method == "POST"
    assert request.url.path == "/api/v1/admin/ip_blocks"
    assert request.content == (
        b"ip=203.0.113.4%2F32&severity=sign_up_block&comment=comment&expires_in=259200"
    )


def test_silence_account_posts_email_notification_true() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={})

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    client.silence_account(
        account_id="123",
        text="reason",
        send_email_notification=True,
    )

    request = requests[0]
    assert request.method == "POST"
    assert request.url.path == "/api/v1/admin/accounts/123/action"
    assert request.content == b"type=silence&text=reason&send_email_notification=true"


def test_list_local_accounts_uses_v2_admin_accounts_with_since_id() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[{"id": "123"}])

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.list_local_accounts(since_id="100") == [{"id": "123"}]

    request = requests[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v2/admin/accounts"
    assert request.url.params["origin"] == "local"
    assert request.url.params["limit"] == "200"
    assert request.url.params["since_id"] == "100"


def test_list_local_accounts_follows_next_link() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json=[{"id": "101"}],
                headers={
                    "Link": (
                        "<https://mastodon.example/api/v2/admin/accounts?page=2>; "
                        'rel="next"'
                    )
                },
            )
        return httpx.Response(200, json=[{"id": "102"}])

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.list_local_accounts() == [{"id": "101"}, {"id": "102"}]

    assert requests[0].url.params["origin"] == "local"
    assert requests[1].url.path == "/api/v2/admin/accounts"
    assert requests[1].url.params["page"] == "2"


def test_list_mention_notifications_uses_v1_notifications_with_min_id() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[{"id": "123"}])

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.list_mention_notifications(since_id="100") == [{"id": "123"}]

    request = requests[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v1/notifications"
    assert request.url.params.get_list("types[]") == ["mention"]
    assert request.url.params["limit"] == "80"
    assert request.url.params["min_id"] == "100"


def test_list_mention_notifications_follows_prev_link_for_newer_pages() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json=[{"id": "101"}],
                headers={
                    "Link": (
                        "<https://mastodon.example/api/v1/notifications?min_id=101>; "
                        'rel="prev"'
                    )
                },
            )
        return httpx.Response(200, json=[{"id": "102"}])

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.list_mention_notifications(since_id="100") == [
        {"id": "101"},
        {"id": "102"},
    ]

    assert requests[0].url.params.get_list("types[]") == ["mention"]
    assert requests[1].url.path == "/api/v1/notifications"
    assert requests[1].url.params["min_id"] == "101"


def test_list_mention_notifications_does_not_follow_links_without_cursor() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=[{"id": "101"}],
            headers={
                "Link": (
                    "<https://mastodon.example/api/v1/notifications?max_id=101>; "
                    'rel="next"'
                )
            },
        )

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.list_mention_notifications() == [{"id": "101"}]
    assert len(requests) == 1


def test_find_ip_block_returns_matching_existing_block() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=[
                {"id": "1", "ip": "203.0.113.1/32"},
                {"id": "2", "ip": "203.0.113.2/32"},
            ],
        )

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.find_ip_block("203.0.113.2/32") == {
        "id": "2",
        "ip": "203.0.113.2/32",
    }
    assert requests[0].url.path == "/api/v1/admin/ip_blocks"
    assert requests[0].url.params["limit"] == "200"


def test_find_ip_block_follows_next_link() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json=[{"id": "1", "ip": "203.0.113.1/32"}],
                headers={
                    "Link": (
                        "<https://mastodon.example/api/v1/admin/ip_blocks?page=2>; "
                        'rel="next"'
                    )
                },
            )
        return httpx.Response(200, json=[{"id": "2", "ip": "203.0.113.2/32"}])

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    assert client.find_ip_block("203.0.113.2/32") == {
        "id": "2",
        "ip": "203.0.113.2/32",
    }
    assert requests[1].url.path == "/api/v1/admin/ip_blocks"
    assert requests[1].url.params["page"] == "2"


def test_list_mention_notifications_rate_limit_raises_with_retry_at() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "60"})

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    try:
        client.list_mention_notifications()
    except RateLimitedError as error:
        assert error.retry_at > datetime.now(UTC)
    else:
        raise AssertionError("expected RateLimitedError")


def test_list_mention_notifications_transport_error_is_retryable_api_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network unavailable")

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    try:
        client.list_mention_notifications()
    except MastodonAPIError as error:
        assert error.status_code is None
    else:
        raise AssertionError("expected MastodonAPIError")


def test_rate_limit_raises_with_retry_at() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "60"})

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    try:
        client.list_local_accounts()
    except RateLimitedError as error:
        assert error.retry_at > datetime.now(UTC)
    else:
        raise AssertionError("expected RateLimitedError")


def test_transport_error_becomes_retryable_mastodon_api_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network unavailable")

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    try:
        client.list_local_accounts()
    except MastodonAPIError as error:
        assert error.status_code is None
    else:
        raise AssertionError("expected MastodonAPIError")


def test_http_error_includes_response_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"error": "Validation failed"})

    client = MastodonClient(
        http=httpx.Client(
            base_url="https://mastodon.example",
            transport=httpx.MockTransport(handler),
        )
    )

    try:
        client.block_ip(
            ip_cidr="203.0.113.4/32",
            severity="no_access",
            comment="comment",
            expires_in=259200,
        )
    except MastodonAPIError as error:
        assert error.status_code == 422
        assert "Validation failed" in str(error)
    else:
        raise AssertionError("expected MastodonAPIError")
