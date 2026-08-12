from .graph import JudgmentGraph
from ..domain.models import InvestigationState
from .planner import Planner
from ..adapters.tools import ToolRegistry


class InvestigationEngine:
    """Compatibility facade; LangGraph owns all investigation flow control."""

    def __init__(self, registry: ToolRegistry, planner: Planner):
        self.graph = JudgmentGraph(registry, planner, scope_approval_mode="legacy")

    def run(self, state: InvestigationState) -> InvestigationState:
        return self.graph.run(state)
