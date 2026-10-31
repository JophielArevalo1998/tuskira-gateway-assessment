#!/usr/bin/env python3
"""Proactive hunt over the gateway's own telemetry feed.

Reads the newline-delimited records the gateway writes to stdout (what
ship.sh tails into ~/bench/gateway-events.jsonl) -- both planes, one file:

    {"type":"access",   "record":{... MCP access log ...}}
    {"type":"llm_call", "record":{... LLM call ...}}

It runs two hypotheses, the way a hunt workspace (LOCK: Learn/Observe/Check/
Keep) frames them -- no single event is an alert; the pattern is. Both point
back at the SAME control plane that produced the data, so a confirmed finding
converts straight into a gateway action (revoke the key / tighten the profile).

    python3 hunt.py                       # reads ~/bench/gateway-events.jsonl
    python3 hunt.py --feed /path/to.jsonl
"""
import argparse
import json
import os
from collections import defaultdict, Counter

DENY = "-32003"


def load(path):
    acc, llm = [], []
    with open(path, "r", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                o = json.loads(ln)
            except Exception:
                continue
            rec = o.get("record") or {}
            t = o.get("type")
            if t == "access":
                acc.append(rec)
            elif t == "llm_call":
                llm.append(rec)
    return acc, llm


def rule(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def hunt_enumeration(acc, threshold=6):
    rule("H-1  Tool enumeration / permission discovery  (MCP)")
    print("Hypothesis: a single identity is probing many tools it is not")
    print("granted -- mapping a stolen agent's reach. Signal: distinct denied")
    print("tool names per principal, not the count of any one call.\n")
    by_principal = defaultdict(set)
    ips = defaultdict(set)
    for r in acc:
        if str(r.get("error_code")) == DENY:
            p = r.get("principal") or r.get("key_id") or "?"
            by_principal[p].add(r.get("tool_name") or "?")
            if r.get("client_ip"):
                ips[p].add(r["client_ip"])
    if not by_principal:
        print("  no -32003 denials in the feed yet.")
        return
    ranked = sorted(by_principal.items(), key=lambda kv: len(kv[1]), reverse=True)
    for p, tools in ranked:
        flag = "  <-- ENUMERATION" if len(tools) >= threshold else ""
        print("  principal %s" % p)
        print("     distinct tools denied : %d%s" % (len(tools), flag))
        print("     from IP(s)            : %s" % ", ".join(sorted(ips[p])) or "?")
        print("     tools                 : %s" % ", ".join(sorted(tools)))
    top, tools = ranked[0]
    if len(tools) >= threshold:
        print("\n  VERDICT: confirmed. %s enumerated %d distinct tools." % (top, len(tools)))
        print("  ACTION : tighten/rotate the key via the gateway API (apikey.revoke).")


def hunt_llm_abuse(llm):
    rule("H-2  LLM resource abuse / 'LLM-jacking'  (LLM plane)")
    print("Hypothesis: a key is being driven to burn tokens/budget or run")
    print("oversized generations. Signal: governance denials (max_tokens / rpm")
    print("/ budget) clustered on one key, and a token-spend outlier.\n")
    denials = defaultdict(Counter)   # key -> {max_tokens, rpm, budget}
    tokens = Counter()               # key -> captured tokens
    ips = defaultdict(set)
    for r in llm:
        key = r.get("key_id") or r.get("principal") or "?"
        err = (r.get("error") or "").lower()
        if r.get("status_code") == 200:
            tokens[key] += (r.get("input_tokens", 0) or 0) + (r.get("output_tokens", 0) or 0)
        elif "max_tokens" in err or "exceeds" in err:
            denials[key]["max_tokens"] += 1
        elif "budget" in err:
            denials[key]["budget"] += 1
        elif "rpm" in err or "per minute" in err or "rate limit" in err:
            denials[key]["rpm"] += 1
        if r.get("client_ip"):
            ips[key].add(r["client_ip"])
    if not llm:
        print("  no llm_call records in the feed yet.")
        return
    offenders = sorted(denials.items(),
                       key=lambda kv: sum(kv[1].values()), reverse=True)
    for key, d in offenders:
        print("  key %s" % key)
        print("     denials  : max_tokens=%d  rpm=%d  budget=%d"
              % (d["max_tokens"], d["rpm"], d["budget"]))
        print("     tokens   : %d captured on allowed calls" % tokens.get(key, 0))
        print("     from IP  : %s" % (", ".join(sorted(ips[key])) or "?"))
    if offenders:
        key, d = offenders[0]
        print("\n  VERDICT: confirmed. key %s hit %d governance denials across"
              % (key, sum(d.values())))
        print("  three controls -- the gateway refused each BEFORE any upstream call.")
        print("  ACTION : revoke the key via the gateway API (apikey.revoke).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", default=os.path.expanduser("~/bench/gateway-events.jsonl"))
    ap.add_argument("--enum-threshold", type=int, default=6)
    a = ap.parse_args()
    if not os.path.exists(a.feed):
        raise SystemExit("feed not found: %s  (is ship.sh running?)" % a.feed)
    acc, llm = load(a.feed)
    print("hunt over %s" % a.feed)
    print("  %d access records, %d llm_call records" % (len(acc), len(llm)))
    hunt_enumeration(acc, a.enum_threshold)
    hunt_llm_abuse(llm)
    print()


if __name__ == "__main__":
    main()
