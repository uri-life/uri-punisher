from __future__ import annotations

import re
from html.parser import HTMLParser

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,30}$")


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        return " ".join(self.parts)


def html_to_text(value: str) -> str:
    parser = _HTMLTextExtractor()
    parser.feed(value)
    return parser.text()


def parse_bare_usernames(content: str) -> list[str]:
    text = html_to_text(content)
    usernames: list[str] = []
    seen: set[str] = set()
    for raw_token in text.split():
        token = raw_token.strip(".,:;!?()[]{}\"'")
        if token.startswith("@") or "@" in token or "." in token:
            continue
        if not USERNAME_RE.fullmatch(token):
            continue
        if token in seen:
            continue
        seen.add(token)
        usernames.append(token)
    return usernames
