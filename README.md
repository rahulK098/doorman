<p align="center">
  <img src="assets/logo.png" alt="Doorman — Prompt Injection Guardrails Library" width="640">
</p>

> Layered prompt-injection defense that checks whether your agent's next action still matches the user's intent - and keeps attacking itself in CI to prove it still holds.

**Status:** pre-alpha, under active development. Phase 1 of 3 (core library + five layers) is implemented; `IntentAligner`, the reference recruiting agent, and `doorman-bench` are next.

## The problem

Every tool-calling agent that reads untrusted content — resumes, emails, web pages, other tools' output — has the same weakness: the input is hostile and the model is gullible. Existing tools mostly answer *"does this text look like an injection?"*. Doorman also answers the harder questions:

- Does the agent's **proposed action** still match what the user asked for?
- Which arguments in that action were **sourced from untrusted content**?
- Is untrusted content being **exfiltrated verbatim** (detected deterministically, no classifier involved)?
- Are several individually-innocent documents **adding up** to an attack across the session?

## Install

```bash
pip install doorman            # core: zero runtime dependencies
pip install "doorman[bench]"   # + the doorman-bench CLI (Phase 3)
```

## Quickstart

```python
from doorman import (
    Guard, Classifier, Isolator, ToolPolicy, OutputScanner,
    ConfirmationGate, SessionRiskTracker, ToolCall, Tagged, Source,
)

guard = Guard(
    classifier=Classifier(),                                   # injection-likelihood score
    isolator=Isolator(),                                       # session-nonce delimiters + canaries
    tool_policy=ToolPolicy(
        {"scoring": ["read_document", "write_ats_score"], "outreach": ["send_email"]},
        always_safe=["read_document"],
    ),
    output_scanner=OutputScanner(),                            # canary leak + provenance-aware scan
    confirmation_gate=ConfirmationGate(irreversible_tools=["send_email"]),
    risk_tracker=SessionRiskTracker(budget=1.5),               # cross-document risk budget
)

session = "sess_123"

# 1. Ingest untrusted content: classified, charged against the risk budget, isolated.
doc = guard.ingest(resume_text, session, origin="resume:cand_42")
if doc.quarantined:
    print(doc.governing.rationale)   # e.g. "Injection likelihood 0.82 >= 0.50 in resume:cand_42. Signals: ..."
else:
    prompt = SYSTEM_PROMPT + "\n" + guard.system_prompt_fragment(session) + "\n" + doc.text

# 2. Before executing any tool call the model proposes, check it.
proposed = ToolCall(
    "send_email",
    {"to": "hr@example.com", "body": Tagged(model_written_summary, Source.UNTRUSTED, "resume:cand_42")},
)
decision = guard.check_tool_call(proposed, session, context="outreach")
if not decision.permits:
    print(decision.rationale)
```

Or wrap the whole step:

```python
step = guard.protect(agent_step, session, context="outreach")
step()   # raises ActionBlocked / ConfirmationRequired with a full rationale
```

Every verdict from every layer — allow, warn, confirm or block — carries a **human-readable rationale**, is written to `guard.events`, and is mirrored to the `doorman` logger.

## The layers

| Layer | What it does | Control or hint? |
|---|---|---|
| `Classifier` | Scores text for injection likelihood. Pluggable backend; the default is dependency-free heuristics. | signal |
| `Isolator` | Wraps untrusted content in delimiters carrying a **per-session random nonce**, neutralizes forged delimiters, mints a **canary token** per document. | control |
| `IntentAligner` *(Phase 2)* | Privilege-separated check that the proposed action matches the user's original task. **Never sees the untrusted content** — enforced in code and tested. | control |
| `ToolPolicy` | Per-context tool allowlist that tightens as the session's risk budget is spent. | control |
| `OutputScanner` | Scans proposed tool-call arguments: canary leaks (deterministic), **provenance-aware** injection scoring (untrusted-sourced args face a stricter threshold), host predicates. | control |
| `ConfirmationGate` | Holds irreversible actions for human approval; escalates to *all* actions when risk is elevated. | control |
| `SessionRiskTracker` | Cross-cutting: accumulates risk across documents and blocked calls so compounding attacks are caught. | control |

Each layer is independently importable and usable without `Guard`. No layer imports another (enforced by a test).

## Why not just use LLM Guard / NeMo Guardrails / LlamaFirewall?

Those are good at *classification* — is this text injection-shaped? Doorman's classifier is deliberately the least interesting layer. What the others don't do, and Doorman does:

1. **Intent-vs-action alignment** as a privilege-separated primitive.
2. **Provenance tracking** of tool-call arguments back to trusted or untrusted sources.
3. **Canary-token exfiltration detection** that no paraphrase can evade.
4. **A session risk budget** so split attacks don't slip under per-message thresholds.
5. **A self-updating benchmark** (`doorman-bench --evolve`, Phase 3) that mutates blocked attacks and retries them against the live pipeline, auto-filing real bypasses as fixtures.

## Threat model in brief

**Assumed:** the attacker controls the full text of one or more untrusted documents in a session, knows Doorman's source, and may split an attack across documents. They do **not** know the per-session nonce or canary values.

**Defended:** direct overrides, hidden/zero-width text, delimiter forgery, metadata injection, indirect injection via tool results, verbatim exfiltration, context escalation, compounding multi-document attacks, and unapproved irreversible actions.

**Out of scope:** attacks that never produce a tool call, model-level jailbreaks with no untrusted content, a malicious host application, and provenance *inference* — Doorman tracks the provenance the host declares via `Tagged`, it cannot know what the model was "inspired by".

No defense that relies on the model's cooperation counts as a control. The system-prompt fragment the `Isolator` provides is a hint; the nonce, canary, policy and gate are the controls.

## Design notes

- **Layers never import each other.** `Guard` is the only place that knows the order; cross-cutting state (`CanaryRegistry`, `SessionRiskTracker`) is passed in explicitly. A test enforces this.
- **Provenance is a wrapper type** (`Tagged(value, source, origin)`), not a global taint registry. It is declared by the host, attached automatically at `ingest()`, and stripped with `ToolCall.plain_args` before the real tool runs.
- **Isolation delimiters carry a per-session nonce** so `</document>`-style forgery is just text. Forged boundaries with the correct nonce are neutralized and logged.
- **Canaries live in the wrapper, not the body**, so a faithful summary doesn't leak them but a verbatim copy does. The check is deterministic — no classifier can be paraphrased around it.
- **The default classifier is heuristic and dependency-free** by design. It's a floor, not a ceiling; swap in `Classifier(backend=...)` or a named model via an extra.
- **Every verdict has a rationale**, including `ALLOW`, so logs are self-explanatory without a rule-id lookup table.

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check . && uv run mypy
```

## License

MIT
