from __future__ import annotations

from uri_punisher.parsing import parse_bare_usernames


def test_parse_bare_usernames_keeps_only_local_bare_names() -> None:
    assert parse_bare_usernames("<p>alice @bob carol@example.test dave.</p>") == [
        "alice",
        "dave",
    ]


def test_parse_bare_usernames_deduplicates_in_message_order() -> None:
    assert parse_bare_usernames("alice bob alice") == ["alice", "bob"]
