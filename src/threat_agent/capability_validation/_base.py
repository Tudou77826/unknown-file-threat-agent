"""Local strict base model — mirrors threat_agent.shared.StrictModel.

The capability-validation package must not import any other threat_agent
package (architecture gate, same discipline as agent_eval / agent_middleware):
it stays extractable as a standalone distribution. Keep the definitions in
sync semantically.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
