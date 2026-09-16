"""Reference recruiting agent — the eval scenario, not the product.

``agent`` is the benchmark target (``doorman-bench run --target
examples.recruiting_agent:agent``). ``undefended`` is the same agent with no
guard, for the baseline.
"""

from .agent import InputDocument, RecruitingAgent, RunResult, build_guard
from .model import GullibleModel, Model, SeenDocument
from .tools import World

agent = RecruitingAgent(guard=build_guard())
undefended = RecruitingAgent(guard=None)

__all__ = [
    "GullibleModel",
    "InputDocument",
    "Model",
    "RecruitingAgent",
    "RunResult",
    "SeenDocument",
    "World",
    "agent",
    "build_guard",
    "undefended",
]
