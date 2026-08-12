from __future__ import annotations

from typing import Protocol

from ...contracts import JudgmentResult, ResponseContext


class ResponseContextPort(Protocol):
    def load(self, judgment: JudgmentResult) -> ResponseContext: ...
