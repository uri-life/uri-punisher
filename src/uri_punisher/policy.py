from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

SECONDS_PER_DAY = 24 * 60 * 60


@dataclass(frozen=True)
class IPAction:
    severity: str
    days: int

    @property
    def expires_in(self) -> int:
        return self.days * SECONDS_PER_DAY


def ip_action_for_score(score: int) -> IPAction | None:
    if score >= 100:
        return IPAction(severity="no_access", days=180)
    if score >= 90:
        return IPAction(severity="no_access", days=90)
    if score >= 80:
        return IPAction(severity="no_access", days=30)
    if score >= 70:
        return IPAction(severity="sign_up_block", days=15)
    if score >= 60:
        return IPAction(severity="sign_up_block", days=7)
    if score >= 50:
        return IPAction(severity="sign_up_block", days=3)
    return None


def should_silence_account(score: int) -> bool:
    return score >= 80


def single_ip_cidr(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    prefix = 32 if address.version == 4 else 128
    return f"{address}/{prefix}"


def abuseipdb_check_url(ip: str) -> str:
    return f"https://www.abuseipdb.com/check/{ipaddress.ip_address(ip)}"


def ip_block_comment(ip: str, score: int) -> str:
    return (
        "Automated single-IP action: "
        f"AbuseIPDB abuse confidence score {score}. "
        f"Evidence: {abuseipdb_check_url(ip)}"
    )


AccountSilenceTextSource = Literal["signup", "login"]


def account_silence_text(
    ip: str,
    score: int,
    *,
    source: AccountSilenceTextSource,
) -> str:
    del ip
    del score
    usage = "이 계정에 로그인할 때" if source == "login" else "이 계정을 만들 때"
    return (
        f"{usage} 사용하신 인터넷 연결 환경이 악용 행위와 연관되어 "
        "있을 가능성이 높아, 계정이 자동 침묵 처리되었습니다."
    )
