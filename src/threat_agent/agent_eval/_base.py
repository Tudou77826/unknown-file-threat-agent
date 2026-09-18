"""Local strict base model — mirrors threat_agent.shared.StrictModel.

The kernel must not import any other threat_agent package (architecture
gate), so the base class is duplicated here on purpose: agent_eval stays
extractable as a standalone distribution, same discipline as
agent_middleware. Keep the two definitions in sync semantically.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
