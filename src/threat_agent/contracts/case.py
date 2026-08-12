from __future__ import annotations

from typing import Any

from .common import ContractModel
from .evidence import Scope


class InitialCase(ContractModel):
    raw_input: dict[str, Any]
    scope: Scope
