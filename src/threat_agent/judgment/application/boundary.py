"""Investigation boundary port: every tool call passes the same gate.

The judgment module defines and consumes this port; concrete policies (for
example the single-host policy owned by case management) are injected by
bootstrap. The port performs call authorization before execution and result
validation before anything may enter the tool ledger, events or the model
context. Denials are structured (``BoundaryDenied``) so the model receives a
stable error code instead of a silently empty result.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from ...contracts import (
    BoundaryDenied,
    InvestigationToolLedger,
    ToolRuntimeContext,
)


class BoundaryViolationError(RuntimeError):
    """Raised when a tool call or result violates the investigation boundary."""

    def __init__(self, denial: BoundaryDenied):
        super().__init__(denial.message)
        self.denial = denial

    @property
    def code(self) -> str:
        return self.denial.code

    @property
    def message(self) -> str:
        return self.denial.message

    @property
    def tool_name(self) -> str:
        return self.denial.tool_name


@runtime_checkable
class InvestigationBoundaryPort(Protocol):
    def authorize_call(
        self,
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> None:
        """Raise ``BoundaryViolationError`` when the call must not execute."""
        ...

    def validate_result(
        self,
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
        tool_name: str,
        result: Any,
    ) -> None:
        """Raise ``BoundaryViolationError`` when a result must not be recorded."""
        ...
