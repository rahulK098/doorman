"""Reference recruiting agent — the eval scenario, not the product.

``agent`` is the benchmark target (``doorman-bench run --target
examples.recruiting_agent:agent``). ``undefended`` is the same agent with no
guard, for the baseline.
"""

from typing import TYPE_CHECKING, Any

from .agent import InputDocument, RecruitingAgent, RunResult, build_guard
from .model import GullibleModel, Model, SeenDocument
from .tools import World

if TYPE_CHECKING:
    from .anthropic_model import AnthropicModel

agent = RecruitingAgent(guard=build_guard())
undefended = RecruitingAgent(guard=None)


def __getattr__(name: str) -> Any:
    """Lazy targets that need the ``anthropic`` extra.

    ``anthropic_agent`` is a benchmark target for ``--mode agent``; importing it
    eagerly would make the whole example package require the extra.
    """
    if name == "AnthropicModel":
        from .anthropic_model import AnthropicModel as _AnthropicModel

        return _AnthropicModel
    if name == "anthropic_agent":
        from .anthropic_model import AnthropicModel as _AnthropicModel

        return RecruitingAgent(model=_AnthropicModel(), guard=build_guard())
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AnthropicModel",
    "GullibleModel",
    "InputDocument",
    "Model",
    "RecruitingAgent",
    "RunResult",
    "SeenDocument",
    "World",
    "agent",
    "anthropic_agent",
    "build_guard",
    "undefended",
]
