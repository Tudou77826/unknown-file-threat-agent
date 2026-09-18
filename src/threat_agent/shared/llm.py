"""Unified graded-retry robustness for every LLM interaction.

Every model call goes through :func:`invoke_llm` so failures are handled by
class, not per-call-site:

- ``parse``    — the model answered but the output failed to parse/validate
                 (e.g. malformed JSON from a structured-output call). Retry with
                 corrective feedback, bounded by ``parse_max_attempts``.
- ``transport``— a transient provider failure (timeout, connection, rate limit,
                 5xx). Retry with linear backoff, bounded by ``transport_max_attempts``.
- ``fatal``    — authentication, bad request, or anything unknown. Re-raise
                 immediately; retrying cannot help and may hide a real bug.

The configured chat model already owns HTTP-layer retries; this layer adds the
corrective retry that a malformed structured-output response needs and a bounded
safety net for transient failures that still bubble up.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from langchain_core.exceptions import OutputParserException
from openai import (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)
from pydantic import ValidationError

ParseError = (OutputParserException, ValidationError)
TransientTransportError = (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)


def classify_llm_error(error: Exception) -> str:
    """Return ``parse``, ``transport`` or ``fatal`` for a raised model error."""

    if isinstance(error, ParseError):
        return "parse"
    if isinstance(error, TransientTransportError):
        return "transport"
    return "fatal"


def invoke_llm(
    invoke: Callable[[], Any],
    *,
    messages: list | None = None,
    build_feedback: Callable[[int, Exception], Any | None] | None = None,
    on_attempt: Callable[[int], None] | None = None,
    on_output: Callable[[int, Any], None] | None = None,
    on_failure: Callable[[int, Exception, str], None] | None = None,
    parse_max_attempts: int = 3,
    transport_max_attempts: int = 2,
    transport_backoff: float = 1.5,
) -> Any:
    """Run one LLM call with graded retry; see module docstring.

    ``invoke`` must return the fully parsed/validated output, or raise
    :data:`ParseError` / :data:`TransientTransportError`. On a parse failure,
    ``build_feedback(attempt, error)`` may return a message to append to
    ``messages`` before the next attempt; both are optional.
    """

    last_error: Exception | None = None
    parse_attempts = 0
    transport_attempts = 0
    while True:
        parse_attempts += 1
        if on_attempt is not None:
            on_attempt(parse_attempts)
        try:
            output = invoke()
        except ParseError as error:
            last_error = error
            if on_failure is not None:
                on_failure(parse_attempts, error, "parse")
            if parse_attempts >= parse_max_attempts:
                break
            feedback = build_feedback(parse_attempts, error) if build_feedback else None
            if messages is not None and feedback is not None:
                messages.append(feedback)
            continue
        except TransientTransportError as error:
            last_error = error
            transport_attempts += 1
            if on_failure is not None:
                on_failure(parse_attempts, error, "transport")
            if transport_attempts < transport_max_attempts:
                time.sleep(transport_backoff * transport_attempts)
                continue
            raise
        except Exception as error:
            if on_failure is not None:
                on_failure(parse_attempts, error, "fatal")
            raise
        if on_output is not None:
            on_output(parse_attempts, output)
        return output
    raise RuntimeError(
        f"LLM call did not produce a valid structured output after {parse_max_attempts} attempts"
    ) from last_error


__all__ = ["classify_llm_error", "invoke_llm"]


def structured_output_method(model) -> str:
    """json_mode is an OpenAI-family capability; Anthropic-family models
    reach structured output through tool calling."""

    module = type(model).__module__
    return "json_mode" if module.startswith("langchain_openai") else "function_calling"
