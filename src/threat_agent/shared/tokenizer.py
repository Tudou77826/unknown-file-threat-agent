"""Lightweight token estimation for context budgeting.

We deliberately avoid a real tokenizer dependency: budgets and truncation only
need a cheap, stable estimate. The heuristic mirrors chrys' mixed-language
estimator — CJK characters cost more than ASCII because most tokenizers pack
fewer CJK characters per token.
"""

from __future__ import annotations

from typing import Any

# CJK and CJK-compatibility/extension ranges commonly encoded as one token each
# in many subword tokenizers, hence weighted higher than ASCII.
_CJK_RANGES = (
    (0x3400, 0x4DBF),   # CJK Extension A
    (0x4E00, 0x9FFF),   # CJK Unified Ideographs
    (0xF900, 0xFAFF),   # CJK Compatibility Ideographs
    (0x20000, 0x2A6DF),  # CJK Extension B
    (0x2F800, 0x2FA1F),  # CJK Compatibility Supplement
)

_CJK_WEIGHT = 0.6
_OTHER_WEIGHT = 0.25


def _is_cjk(char: str) -> bool:
    code = ord(char)
    return any(lo <= code <= hi for lo, hi in _CJK_RANGES)


def estimate_tokens(text: Any) -> int:
    """Estimate token count for a string (or any JSON-serializable value)."""
    if not isinstance(text, str):
        text = str(text)
    total = 0.0
    for char in text:
        total += _CJK_WEIGHT if _is_cjk(char) else _OTHER_WEIGHT
    return max(1, int(total))


def estimate_messages_tokens(messages: list[Any]) -> int:
    """Estimate token count for a list of LangChain messages.

    Only ``content`` is measured; tool_calls and metadata are excluded since
    this estimate is used for relative budgeting, not exact accounting.
    """
    total = 0
    for message in messages:
        content = getattr(message, "content", None)
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, str):
                    total += estimate_tokens(part)
                elif isinstance(part, dict):
                    total += estimate_tokens(str(part))
        elif content is not None:
            total += estimate_tokens(str(content))
    return max(1, total)
