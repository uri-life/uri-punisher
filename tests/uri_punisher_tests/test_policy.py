from __future__ import annotations

from uri_punisher.policy import (
    SECONDS_PER_DAY,
    account_silence_text,
    ip_action_for_score,
    should_silence_account,
    single_ip_cidr,
)


def test_ip_policy_score_boundaries() -> None:
    cases = {
        49: None,
        50: ("sign_up_block", 3),
        59: ("sign_up_block", 3),
        60: ("sign_up_block", 7),
        69: ("sign_up_block", 7),
        70: ("sign_up_block", 15),
        79: ("sign_up_block", 15),
        80: ("no_access", 30),
        89: ("no_access", 30),
        90: ("no_access", 90),
        99: ("no_access", 90),
        100: ("no_access", 180),
    }

    for score, expected in cases.items():
        action = ip_action_for_score(score)
        if expected is None:
            assert action is None
        else:
            severity, days = expected
            assert action is not None
            assert action.severity == severity
            assert action.days == days
            assert action.expires_in == days * SECONDS_PER_DAY


def test_account_policy_only_silences_at_80_or_above() -> None:
    assert not should_silence_account(50)
    assert not should_silence_account(60)
    assert not should_silence_account(70)
    assert should_silence_account(80)


def test_single_ip_cidr_never_expands_to_network_range() -> None:
    assert single_ip_cidr("203.0.113.8") == "203.0.113.8/32"
    assert single_ip_cidr("2001:db8::1") == "2001:db8::1/128"


def test_signup_account_silence_text_explains_abuse_risk_without_url() -> None:
    text = account_silence_text("203.0.113.8", 80, source="signup")

    assert (
        text == "이 계정을 만들 때 사용하신 인터넷 연결 환경이 "
        "악용 행위와 연관되어 있을 가능성이 높아, "
        "계정이 자동 침묵 처리되었습니다."
    )
    assert "203.0.113.8" not in text
    assert "80점" not in text
    assert "AbuseIPDB" not in text
    assert "https://" not in text


def test_login_account_silence_text_uses_dm_wording() -> None:
    text = account_silence_text("203.0.113.8", 80, source="login")

    assert (
        text == "이 계정에 로그인할 때 사용하신 인터넷 연결 환경이 "
        "악용 행위와 연관되어 있을 가능성이 높아, "
        "계정이 자동 침묵 처리되었습니다."
    )
    assert "203.0.113.8" not in text
    assert "80점" not in text
    assert "AbuseIPDB" not in text
    assert "https://" not in text
