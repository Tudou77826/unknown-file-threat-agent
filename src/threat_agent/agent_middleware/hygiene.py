"""History hygiene before every model call.

Providers occasionally leave streaming artifacts inside message content
blocks — for example a ``partial_json`` key on a tool-use-shaped block,
carrying ``None`` or a truncated string when the model emitted a malformed
tool call. The artifact itself is harmless in state, but the next request
formatting feeds it to ``json.loads`` verbatim, and one malformed block then
crashes the whole run.

This middleware normalizes such blocks deterministically before the model
sees them again: streaming artifacts are folded into the block's input (when
parseable) or dropped, and ``None`` inputs become empty dicts. History that
is already clean is passed through untouched (``None`` update, zero cost).
"""

from __future__ import annotations

import json
import uuid
from typing import Any, TypeVar

from langchain.agents.middleware.types import AgentMiddleware, add_messages
from langchain_core.messages import AIMessage, AnyMessage
from langchain_core.messages import RemoveMessage
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from typing_extensions import Annotated, Required, TypedDict

from typing_extensions import NotRequired

ContextT = TypeVar("ContextT")
ResponseT = TypeVar("ResponseT")

# Content-block keys that only exist while a streamed tool call is being
# assembled; they are never valid request content.
_STREAMING_ARTIFACT_KEYS = ("partial_json",)


class HygieneState(TypedDict, total=False):
    messages: Required[Annotated[list[AnyMessage], add_messages]]


def _clean_block(block: Any) -> tuple[Any, bool]:
    """Return (possibly cleaned block, changed?). Only dict blocks with a
    streaming artifact or a ``None`` input/args need touching."""
    if not isinstance(block, dict):
        return block, False
    cleaned = dict(block)
    changed = False
    for key in _STREAMING_ARTIFACT_KEYS:
        if key in cleaned:
            artifact = cleaned.pop(key)
            changed = True
            if isinstance(artifact, str) and artifact.strip():
                try:
                    parsed = json.loads(artifact)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict) and parsed:
                    # Fold the parseable payload into the block input unless
                    # a real input is already there.
                    if not cleaned.get("input"):
                        cleaned["input"] = parsed
    for key in ("input", "args"):
        if key in cleaned and cleaned[key] is None:
            cleaned[key] = {}
            changed = True
    return cleaned, changed


def _message_needs_cleaning(message: AnyMessage) -> bool:
    content = getattr(message, "content", None)
    if not isinstance(content, list):
        return False
    return any(
        isinstance(block, dict)
        and (
            any(key in block for key in _STREAMING_ARTIFACT_KEYS)
            or ("input" in block and block["input"] is None)
            or ("args" in block and block["args"] is None)
        )
        for block in content
    )


class HistoryHygieneMiddleware(AgentMiddleware[HygieneState, ContextT, ResponseT]):
    """Normalize provider streaming artifacts in history before model calls."""

    state_schema = HygieneState  # type: ignore[assignment]

    def before_model(self, state, runtime) -> dict[str, Any] | None:
        messages = state["messages"]
        if not any(
            _message_needs_cleaning(message) for message in messages
            if isinstance(message, AIMessage)
        ):
            return None
        rebuilt: list[AnyMessage] = []
        for message in messages:
            if isinstance(message, AIMessage) and _message_needs_cleaning(message):
                blocks: list[Any] = []
                for block in message.content:
                    cleaned, _ = _clean_block(block)
                    blocks.append(cleaned)
                message = message.model_copy(update={"content": blocks})
            if message.id is None:
                # Replacements merge by id; every re-added message needs one
                # (same discipline as the official summarization middleware).
                message = message.model_copy(update={"id": str(uuid.uuid4())})
            rebuilt.append(message)
        return {
            "messages": [RemoveMessage(id=REMOVE_ALL_MESSAGES), *rebuilt],
        }

    async def abefore_model(self, state, runtime) -> dict[str, Any] | None:
        return self.before_model(state, runtime)


__all__ = ["HistoryHygieneMiddleware"]
