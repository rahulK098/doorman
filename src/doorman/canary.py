"""Canary tokens: a deterministic exfiltration check.

The ``Isolator`` mints a token per isolated block; the ``OutputScanner`` looks
for any of this session's tokens in outbound tool-call arguments. No model is
involved, so this control cannot be paraphrased around.

See docs/adr/0007-canary-tokens-live-in-isolator.md.
"""

from __future__ import annotations

import re
import secrets
import threading
from dataclasses import dataclass

CANARY_PREFIX = "dmc-"
_CANARY_RE = re.compile(re.escape(CANARY_PREFIX) + r"[0-9a-f]{12}")


@dataclass(frozen=True)
class CanaryHit:
    token: str
    session_id: str  # session the token was minted for
    origin: str | None  # what document it was attached to


class CanaryRegistry:
    """Mints and recognizes canary tokens, per session."""

    def __init__(self) -> None:
        self._by_token: dict[str, tuple[str, str | None]] = {}
        self._by_session: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def mint(self, session_id: str, origin: str | None = None) -> str:
        token = CANARY_PREFIX + secrets.token_hex(6)
        with self._lock:
            self._by_token[token] = (session_id, origin)
            self._by_session.setdefault(session_id, set()).add(token)
        return token

    def tokens_for(self, session_id: str) -> frozenset[str]:
        with self._lock:
            return frozenset(self._by_session.get(session_id, ()))

    def find(self, text: str) -> list[CanaryHit]:
        """All known canary tokens present in ``text`` (any session)."""
        hits: list[CanaryHit] = []
        with self._lock:
            for match in _CANARY_RE.finditer(text):
                token = match.group(0)
                known = self._by_token.get(token)
                if known is not None:
                    hits.append(CanaryHit(token=token, session_id=known[0], origin=known[1]))
        return hits

    def forget(self, session_id: str) -> None:
        with self._lock:
            for token in self._by_session.pop(session_id, ()):
                self._by_token.pop(token, None)

    @staticmethod
    def redact(text: str) -> str:
        """Replace canary-shaped substrings so they don't leak via logs."""
        return _CANARY_RE.sub(CANARY_PREFIX + "…", text)
