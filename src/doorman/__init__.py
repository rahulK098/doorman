"""Doorman — layered prompt-injection defense for tool-calling AI agents.

Quickstart::

    from doorman import Guard, Classifier, Isolator, ToolPolicy, OutputScanner, ConfirmationGate
    from doorman import SessionRiskTracker, ToolCall

    guard = Guard(
        classifier=Classifier(),
        isolator=Isolator(),
        tool_policy=ToolPolicy({"scoring": ["read_document"], "outreach": ["send_email"]}),
        output_scanner=OutputScanner(),
        confirmation_gate=ConfirmationGate(irreversible_tools=["send_email"]),
        risk_tracker=SessionRiskTracker(),
    )

    doc = guard.ingest(resume_text, session_id="sess_1", origin="resume:42")
    prompt = system_prompt + guard.system_prompt_fragment("sess_1") + doc.text
    decision = guard.check_tool_call(ToolCall("send_email", {...}), "sess_1", context="outreach")
"""

from doorman.canary import CanaryRegistry
from doorman.errors import (
    ActionBlocked,
    ConfirmationRequired,
    ContentQuarantined,
    DoormanError,
    MissingExtra,
    PrivilegeViolation,
)
from doorman.events import Event, EventLog
from doorman.guard import Guard, GuardDecision, Ingested
from doorman.layers import (
    AlignmentBackend,
    AlignmentJudgement,
    AlignmentResult,
    Classifier,
    ClassifierBackend,
    ConfirmationGate,
    HeuristicBackend,
    IntentAligner,
    IsolatedBlock,
    Isolator,
    KeywordAlignmentBackend,
    OutputScanner,
    ToolPolicy,
)
from doorman.session import SessionRiskTracker
from doorman.types import Decision, Source, Tagged, ToolCall, Verdict, untag

__version__ = "0.1.0.dev0"

__all__ = [
    "ActionBlocked",
    "AlignmentBackend",
    "AlignmentJudgement",
    "AlignmentResult",
    "CanaryRegistry",
    "Classifier",
    "ClassifierBackend",
    "ConfirmationGate",
    "ConfirmationRequired",
    "ContentQuarantined",
    "Decision",
    "DoormanError",
    "Event",
    "EventLog",
    "Guard",
    "GuardDecision",
    "HeuristicBackend",
    "Ingested",
    "IntentAligner",
    "IsolatedBlock",
    "Isolator",
    "KeywordAlignmentBackend",
    "MissingExtra",
    "OutputScanner",
    "PrivilegeViolation",
    "SessionRiskTracker",
    "Source",
    "Tagged",
    "ToolCall",
    "ToolPolicy",
    "Verdict",
    "__version__",
    "untag",
]
