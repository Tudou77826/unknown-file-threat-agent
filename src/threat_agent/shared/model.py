from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model used by internal domain objects and public contracts."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
