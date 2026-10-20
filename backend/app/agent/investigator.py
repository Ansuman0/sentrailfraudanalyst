"""LangGraph investigation agent.

mask_pii -> summarize_activity -> retrieve_guidance -> write_summary
         -> draft_str -> verify_figures -> unmask_pii
Each step is small, so the trace shown to the analyst is easy to follow.
"""
import json
from typing import TypedDict
from langgraph.graph import StateGraph, END

from app.agent import llm, rag, masking, guardrails

SYSTEM = ("You are an AML investigator assistant at a regulated payments company. "
          "Use ONLY the facts provided. Never invent amounts, dates or names. "
          "If something is unknown, say it is unknown. Refer to guidance by its [ref] number.")


class CaseState(TypedDict, total=False):
    facts: dict
    masked_facts: str
    mapping: dict
    activity: str
    guidance: list
    summary: str
    str_draft: str
    verification: dict
    steps: list


def _step(state, name):
    state.setdefault("steps", []).append(name)
    return state


def mask_pii(s: CaseState):
    s["masked_facts"], s["mapping"] = masking.mask(json.dumps(s["facts"], default=str, indent=1))
    return _step(s, "Masked personal data before analysis")


def summarize_activity(s: CaseState):
    s["activity"] = llm.chat(SYSTEM, "Summarize the customer's activity in 4 short bullet points, "
                             "comparing it with their profile:\n" + s["masked_facts"])
    return _step(s, "Summarized account activity")


def retrieve_guidance(s: CaseState):
    reasons = " ".join(r["text"] for r in s["facts"].get("reasons", []))
    s["guidance"] = rag.retrieve(f"money laundering indicators {reasons}")
    return _step(s, f"Found {len(s['guidance'])} relevant guidance passages")


def write_summary(s: CaseState):
    refs = "\n".join(f"[{g['ref']}] {g['source']} p.{g['page']}: {g['text'][:500]}" for g in s["guidance"])
    s["summary"] = llm.chat(SYSTEM, f"Facts:\n{s['masked_facts']}\n\nActivity:\n{s['activity']}\n\n"
                            f"Guidance:\n{refs}\n\nWrite a 120-word case summary explaining why this "
                            "activity is or is not suspicious, citing [ref] numbers.")
    return _step(s, "Wrote case summary")


def draft_str(s: CaseState):
    s["str_draft"] = llm.chat(SYSTEM, f"Facts:\n{s['masked_facts']}\n\nSummary:\n{s['summary']}\n\n"
                              "Draft a suspicious transaction report narrative with these headings: "
                              "Who, What, When, Where, Why suspicious, Actions taken. Plain factual language.")
    return _step(s, "Drafted STR narrative")


def verify_figures(s: CaseState):
    s["verification"] = guardrails.verify(s["str_draft"] + " " + s["summary"], s["facts"])
    return _step(s, f"Checked {s['verification']['checked']} figures against transaction data")


def unmask_pii(s: CaseState):
    for k in ("activity", "summary", "str_draft"):
        s[k] = masking.unmask(s[k], s["mapping"])
    s.pop("mapping", None); s.pop("masked_facts", None)
    return _step(s, "Restored personal data for the analyst view")


def build_agent():
    g = StateGraph(CaseState)
    order = [mask_pii, summarize_activity, retrieve_guidance, write_summary, draft_str, verify_figures, unmask_pii]
    for fn in order:
        g.add_node(fn.__name__, fn)
    g.set_entry_point(order[0].__name__)
    for a, b in zip(order, order[1:]):
        g.add_edge(a.__name__, b.__name__)
    g.add_edge(order[-1].__name__, END)
    return g.compile()


agent = build_agent()


def investigate(facts: dict) -> dict:
    return agent.invoke({"facts": facts})
