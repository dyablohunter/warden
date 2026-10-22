"""The LLM tool-calling loop."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from warden import prompts
from warden.llm import LLMError
from warden.tools import ToolContext, Toolbox

log = logging.getLogger("warden.agent")

# In-run context management. Every step resends the conversation, so it is kept small continuously:
#  1. aging (every step): only the last FRESH_ROUNDS tool rounds keep full output; older outputs shrink to AGED_KEEP chars
#  2. checkpoint (over budget): the model writes a working summary and the conversation restarts from it
FRESH_ROUNDS = 2
AGED_KEEP = 600
AGE_TRIGGER = 16_000  # trim in batches: each trim changes the prompt prefix (cache miss), so do it rarely and fully
CONTEXT_CHAR_BUDGET = 60_000  # ~15k tokens of conversation on top of the static (cached) prefix
MAX_CHECKPOINTS = 3
ELIDED = "\n...[older output trimmed to save context; re-run the command if you need it again]"
CHECKPOINT_PROMPT = (
    "CONTEXT CHECKPOINT. Do not call any tool now. Write a compact working summary (max ~250 words) of this run so far: "
    "facts established (with the key evidence), actions already taken and their results, what is still open, and your "
    "next 1-3 steps. The conversation will be replaced by this summary, so include everything you still need."
)
# step limits per task kind (capped by AGENT_MAX_STEPS); deep work continues in incident follow-ups
STEPS = {"routine": 15, "events": 15, "incident": 20, "onboarding": 30}


@dataclass
class Task:
    kind: str  # routine | events | incident | ask
    name: str
    prompt: str
    incident_id: int | None = None

    def max_steps(self, cap: int) -> int:
        return min(cap, STEPS.get(self.kind, cap))


@dataclass
class AgentResult:
    status: str
    severity: str
    title: str
    summary: str
    notify: bool
    changes: list[str] = field(default_factory=list)
    steps: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_cached: int = 0
    error: str | None = None
    emailed: bool = False


def _size(messages: list[dict]) -> int:
    return sum(len(m.get("content") or "") + len(json.dumps(m.get("tool_calls") or "")) for m in messages)


def age(messages: list[dict], force: bool = False) -> int:
    """Always-on compaction: tool outputs older than the last FRESH_ROUNDS tool rounds are trimmed.

    Trimming is batched (only once AGE_TRIGGER chars of stale output accumulate), because every trim
    changes the prompt prefix and costs a provider cache miss. Trimmed messages never change again,
    so the prefix up to the last trim stays byte-identical and keeps hitting the cache.
    """
    rounds = [i for i, m in enumerate(messages) if m["role"] == "assistant" and m.get("tool_calls")]
    if len(rounds) <= FRESH_ROUNDS:
        return 0
    cutoff = rounds[-FRESH_ROUNDS]
    stale = [m for m in messages[2:cutoff] if m["role"] == "tool" and len(m.get("content") or "") > AGED_KEEP + len(ELIDED)
             and not m["content"].endswith(ELIDED)]
    if not force and sum(len(m["content"]) for m in stale) < AGE_TRIGGER:
        return 0
    for m in stale:
        m["content"] = m["content"][:AGED_KEEP] + ELIDED
    return len(stale)


def fallback_summary(messages: list[dict]) -> str:
    """Deterministic checkpoint when the model can't summarise: the tool calls made and the head of each result."""
    lines = []
    results = {m["tool_call_id"]: m.get("content") or "" for m in messages if m["role"] == "tool"}
    for m in messages:
        for tc in m.get("tool_calls") or []:
            out = results.get(tc["id"], "").replace("\n", " ")[:200]
            lines.append(f"- {tc['function']['name']} {tc['function']['arguments'][:200]} -> {out}")
    return "Tool calls so far (automatic summary):\n" + "\n".join(lines[-30:])


def compact(messages: list[dict]) -> None:
    """Last resort (checkpoints exhausted): force-age, then shorten all but the newest tool output."""
    age(messages, force=True)
    if _size(messages) > CONTEXT_CHAR_BUDGET:
        for m in messages[2:-1]:
            c = m.get("content") or ""
            if m["role"] == "tool" and len(c) > AGED_KEEP + len(ELIDED) and not c.endswith(ELIDED):
                m["content"] = c[:AGED_KEEP] + ELIDED


class Agent:
    def __init__(self, settings, db, llm, bans=None, firewall=None, mailer=None, sampler=None):
        self.s, self.db, self.llm = settings, db, llm
        self.bans, self.firewall, self.mailer, self.sampler = bans, firewall, mailer, sampler
        self.toolbox = Toolbox(settings)

    def run(self, task: Task) -> AgentResult:
        run_id = self.db.run_start(task.kind, task.name)
        ctx = ToolContext(settings=self.s, db=self.db, bans=self.bans, firewall=self.firewall, mailer=self.mailer,
                          sampler=self.sampler, run_id=run_id, actor=f"{task.kind}:{task.name}")
        messages = [
            {"role": "system", "content": prompts.system_prompt(self.s)},
            {"role": "user", "content": task.prompt},
        ]
        tools = self.toolbox.schemas()
        tin = tout = cached = steps = checkpoints = 0
        nudged = warned = False
        error = None
        started = time.time()
        max_steps = task.max_steps(self.s.max_steps)
        token_cap = self.s.max_tokens_per_run
        try:
            while steps < max_steps:
                if tin - cached * 0.9 > token_cap:
                    error = f"token cap reached ({tin} > {token_cap} input tokens)"
                    break
                steps += 1
                final = steps == max_steps or tin - cached * 0.9 > token_cap * 0.9
                if final:  # hard stop: only `finish` is offered, so every run ends with a real report
                    messages.append({"role": "user", "content": "FINAL STEP: call `finish` now with your report (open an incident for anything unfinished first is no longer possible — put the next steps in the summary)."})
                resp = self.llm.chat(messages, [t for t in tools if t["name"] == "finish"] if final else tools)
                tin += resp.usage.get("in", 0)
                tout += resp.usage.get("out", 0)
                cached += resp.usage.get("cached", 0)
                messages.append(resp.message)
                if not resp.tool_calls:
                    if nudged:
                        break
                    messages.append({"role": "user", "content": "You must end by calling the `finish` tool with your report."})
                    nudged = True
                    continue
                for tc in resp.tool_calls:
                    if ctx.result is not None and tc.name != "finish":
                        out = "ignored: run already finished"
                    elif final and tc.name != "finish":
                        out = "BLOCKED: final step — only `finish` is allowed now"
                    else:
                        log.info("[%s] tool %s %s", task.name, tc.name, json.dumps(tc.arguments)[:300])
                        out = self.toolbox.dispatch(ctx, tc.name, tc.arguments, tc.parse_error)
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})
                if ctx.result is not None or final:
                    break
                if not warned and (steps >= max_steps - 3 or tin - cached * 0.9 > token_cap * 0.7):
                    messages.append({"role": "user", "content": "You are almost out of budget for this run. Wrap up now: record remaining work as an incident (with the next step) so a follow-up run continues it, then call finish."})
                    warned = True
                age(messages)
                if _size(messages) > CONTEXT_CHAR_BUDGET and checkpoints < MAX_CHECKPOINTS:
                    messages, usage = self.checkpoint(messages, tools)
                    tin, tout, cached = tin + usage.get("in", 0), tout + usage.get("out", 0), cached + usage.get("cached", 0)
                    checkpoints += 1
                    log.info("[%s] context checkpoint #%d: conversation replaced by a summary", task.name, checkpoints)
                elif _size(messages) > CONTEXT_CHAR_BUDGET:
                    compact(messages)
        except LLMError as exc:
            error = f"LLM error: {exc}"
            log.error("[%s] %s", task.name, error)

        if ctx.result is None:
            last_text = next((m.get("content") for m in reversed(messages) if m["role"] == "assistant" and m.get("content")), "")
            ctx.result = {
                "status": "error" if error and error.startswith("LLM") else "incomplete",
                "severity": "medium" if ctx.changes else "info",
                "title": f"{task.name}: run {'failed' if error else 'did not finish'}",
                "summary": (error or f"Agent stopped without calling finish ({steps} steps).") + (f"\n\nLast message:\n{last_text[:2000]}" if last_text else ""),
                "notify": bool(ctx.changes),
            }
        r = ctx.result
        if checkpoints:
            r["summary"] += f"\n\n(context was checkpointed {checkpoints}x during this run)"
        self.db.run_finish(run_id, status=r["status"], severity=r["severity"], summary=r["summary"][:4000], steps=steps,
                           tokens_in=tin, tokens_out=tout, tokens_cached=cached, error=error)
        log.info("[%s] finished status=%s severity=%s steps=%d tokens in=%d (cached %d) out=%d in %.0fs", task.name, r["status"], r["severity"], steps, tin, cached, tout, time.time() - started)
        return AgentResult(status=r["status"], severity=r["severity"], title=r["title"], summary=r["summary"], notify=r["notify"],
                           changes=ctx.changes, steps=steps, tokens_in=tin, tokens_out=tout, tokens_cached=cached, error=error, emailed=ctx.emailed)

    def checkpoint(self, messages: list[dict], tools: list[dict]) -> tuple[list[dict], dict]:
        """Ask the model for a working summary, then restart the conversation from it (system + task + summary)."""
        usage: dict = {}
        summary = ""
        try:
            resp = self.llm.chat(messages + [{"role": "user", "content": CHECKPOINT_PROMPT}], tools)
            usage = resp.usage
            summary = (resp.content or "").strip()
        except LLMError as exc:
            log.warning("checkpoint summary failed: %s", exc)
        if len(summary) < 40:
            summary = fallback_summary(messages)
        restarted = messages[:2] + [{"role": "user", "content": (
            "## Progress so far (context checkpoint — earlier steps of THIS run, summarised)\n"
            f"{summary[:4000]}\n\nContinue from here. Don't repeat completed steps; re-run a command only if you need its exact output.")}]
        return restarted, usage
