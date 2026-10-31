#!/usr/bin/env python3
"""Build an AiSOC scenario for the prompt-injection example, from the gateway's
OWN telemetry feed.

It reads ~/bench/gateway-events.jsonl, finds MCP tools/call records whose
captured request body carries a prompt-injection payload (content-based, not by
agent name), and emits an aisoc-sandbox scenario JSON describing the incident --
so AiSOC investigates exactly what the gateway recorded.

Requires the feed to include bodies: bring the gateway up with
GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true (see the runbook). Pure stdlib.

  python3 adapt_inject.py
  aisoc-sandbox demo --file ~/bench/scenario-injection.json
"""
import base64
import json
import os
import time
from collections import Counter

FEED = os.path.expanduser("~/bench/gateway-events.jsonl")
OUT = os.path.expanduser("~/bench/scenario-injection.json")

INDICATORS = [
    "ignore all previous", "ignore previous instructions", "system prompt",
    "system override", "you are now dan", "disable all", "exfil",
    "/etc/shadow", "attacker.example", "evil.example", "delete the audit",
    "override:", "reveal your", "jailbreak",
]


def body_text(rec):
    """Decode the captured request body and return just the tool-call argument
    text (the echo message), so matching and snippets read cleanly."""
    b = rec.get("request_body")
    if not b:
        return ""
    raw = b
    if isinstance(b, str):
        try:
            raw = base64.b64decode(b).decode("utf-8", "replace")
        except Exception:
            raw = b
    try:
        args = (json.loads(raw).get("params", {}) or {}).get("arguments", {}) or {}
        vals = [v for v in args.values() if isinstance(v, str)]
        if vals:
            return " ".join(vals)
    except Exception:
        pass
    return raw


def main():
    if not os.path.exists(FEED):
        raise SystemExit("feed not found: %s (is ship.sh running?)" % FEED)
    events, snippets = [], []
    principals, ips = Counter(), Counter()
    with open(FEED, errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                o = json.loads(ln)
            except Exception:
                continue
            if o.get("type") != "access":
                continue
            r = o.get("record") or {}
            if r.get("method") != "tools/call":
                continue
            txt = body_text(r).lower()
            if not any(k in txt for k in INDICATORS):
                continue
            p = r.get("principal") or r.get("key_id") or "?"
            ip = r.get("client_ip") or "?"
            principals[p] += 1
            ips[ip] += 1
            events.append({
                "uuid": r.get("request_id") or r.get("correlation_id") or "",
                "published": r.get("timestamp") or "",
                "eventType": "mcp.tool.call.suspicious_input",
                "actor": p,
                "client_ip": ip,
                "geo": "",
            })
            raw = body_text(r)
            if raw and len(snippets) < 3:
                snippets.append(raw[:160].replace("\n", " "))

    if not events:
        raise SystemExit(
            "no injection payloads found in the feed.\n"
            "Make sure the gateway is up with GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true\n"
            "and that you ran the injection step AFTER that restart.")

    offender = principals.most_common(1)[0][0]
    ip = ips.most_common(1)[0][0]
    scenario = {
        "id": "inj-%s" % time.strftime("%Y%m%d-%H%M%S"),
        "title": "Prompt injection via MCP tool input (echo)",
        "narrative": (
            "%d tool-calls carrying prompt-injection payloads were forwarded by "
            "key %s from %s. The gateway passed them (HTTP 200) -- it does not "
            "judge content -- but captured each payload in its access log. "
            "Example payload: \"%s\". Contain the agent identity and add a "
            "content rule." % (len(events), offender, ip,
                               snippets[0] if snippets else "")),
        "severity": "high",
        "mitre_techniques": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0054 LLM Jailbreak",
            "T1059 Command and Scripting Interpreter (attempted)",
        ],
        "entities": {"user": offender, "ip_a": ip, "ip_b": "",
                     "asset": "everything (MCP echo tool)"},
        "events": events,
        "recommended_actions": [
            {"name": "gateway.apikey.revoke", "args": {"principal": offender}},
            {"name": "gateway.profile.tighten",
             "args": {"agent": offender, "allow": ["echo"]}},
            {"name": "gateway.content_rule.add",
             "args": {"pattern": "ignore previous instructions"}},
        ],
    }
    with open(OUT, "w") as f:
        json.dump(scenario, f, indent=2)
    print("wrote %s" % OUT)
    print("  injection events : %d" % len(events))
    print("  offender         : %s  from %s" % (offender, ip))
    print("  payloads seen    :")
    for s in snippets:
        print("     - %s" % s)
    print("\nNow run:  aisoc-sandbox demo --file %s" % OUT)


if __name__ == "__main__":
    main()
