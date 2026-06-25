from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import httpx


class AbuseIPDBError(RuntimeError):
    pass


@dataclass
class AbuseIPDBClient:
    api_key: str
    http: httpx.Client

    @classmethod
    def create(cls, api_key: str, timeout: float = 20.0) -> AbuseIPDBClient:
        return cls(
            api_key=api_key,
            http=httpx.Client(
                base_url="https://api.abuseipdb.com/api/v2",
                timeout=timeout,
                headers={
                    "Accept": "application/json",
                    "Key": api_key,
                },
            ),
        )

    def check_ip(self, ip: str) -> int:
        canonical_ip = str(ipaddress.ip_address(ip))
        response = self.http.get(
            "/check",
            params={
                "ipAddress": canonical_ip,
                "maxAgeInDays": "90",
            },
        )
        if response.status_code >= 400:
            raise AbuseIPDBError(
                f"AbuseIPDB check failed for {canonical_ip}: HTTP {response.status_code}"
            )
        data = response.json().get("data", {})
        return int(data.get("abuseConfidenceScore", 0))
