"""Middleware event types and observation callbacks.

Middlewares report what they did (rejections, budget transitions) through
an ``EventSink`` callback. The package defines only the event shape; the
business side adapts events into its own run-event stream.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class MiddlewareEvent:
    """One middleware observation.

    ``detail`` carries identifiers and counters only; unauthorized object
    content must never enter an event.
    """

    kind: str
    tool_name: str | None = None
    detail: dict = field(default_factory=dict)


EventSink = Callable[[MiddlewareEvent], None]


def null_sink(event: MiddlewareEvent) -> None:
    """Default no-op sink."""
