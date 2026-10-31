#!/usr/bin/env python3
"""Example 1 - build an AiSOC scenario from the gateway's own telemetry feed.

Reads ~/bench/gateway-events.jsonl (what ship.sh tails) and turns the MCP
access records into an aisoc-sandbox scenario: it classifies events by
outcome (off-profile denial -32003, auth failure 401, lockout 429, allowed
tools/call), picks the offender as the principal with the most denials, and
emits the DETECT->TRIAGE->HUNT->RESPOND scenario JSON. Pure stdlib.

  python3 adapt.py
  aisoc-sandbox demo --file ~/bench/scenario.json
"""
import json
import os
import time
from collections import Counter, defaultdict

FEED = os.path.expanduser("~/bench/gateway-events.jsonl")
OUT = os.path.expanduser("~/bench/scenario.json")
DENY = "-32003"


def classify(r):
    sc = r.get("status_code")
    if str(r.get("error_code")) == DENY:
        return "agent.tool.denied"
    if sc == 401:
        return "auth.failure"
    if sc == 429:
        return "auth.lockout"
    if r.get("method") == "tools/call":
        return "agent.tool.call"
    return None


def main():
    if not os.path.exists(FEED):
        raise SystemExit("feed not found: %s (is ship.sh running?)" % FEED)
    denials = Counter()      # principal -> off-profile denials
    ips = defaultdict(set)   # principal -> client IPs
    attacker_ips = Counter()  # IP -> auth failures/lockouts
    events = []
    kinds = Counter()
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
            k = classify(r)
            if not k:
                continue
            kinds[k] += 1
            p = r.get("principal") or r.get("key_id") or "?"
            ip = r.get("client_ip") or ""
            if k == "agent.tool.denied":
                denials[p] += 1
                if ip:
                    ips[p].add(ip)
            if k in ("auth.failure", "auth.lockout") and ip:
                attacker_ips[ip] += 1
            events.append({"uuid": r.get("request_id") or "", "published": r.get("timestamp") or "",
                           "eventType": k, "actor": p, "client_ip": ip, "geo": ""})

    if not denials and not attacker_ips:
        raise SystemExit("no attack signal in the feed (run gw_traffic.py first; is ship.sh running?)")

    offender = denials.most_common(1)[0][0] if denials else "?"
    off_ip = sorted(ips[offender])[0] if ips.get(offender) else "?"
    attacker_ip = attacker_ips.most_common(1)[0][0] if attacker_ips else ""

    scenario = {
        "id": "gw-%s" % time.strftime("%Y%m%d-%H%M%S"),
        "title": "Compromised agent + credential brute force",
        "narrative": (
            "Agent key %s probed tools outside its profile (%d x -32003) and spiked call "
            "volume; a credential brute force hit from %s (auth failures -> lockout). "
            "The gateway enforced and logged all of it. Contain the offender and confirm "
            "the lockout." % (offender, denials.get(offender, 0), attacker_ip or "an attacker IP")),
        "severity": "high",
        "mitre_techniques": ["T1069 Permission Groups Discovery", "T1078 Valid Accounts",
                             "T1110 Brute Force"],
        "entities": {"user": offender, "ip_a": off_ip, "ip_b": attacker_ip,
                     "asset": "everything (MCP connector)"},
        "events": events[:50],
        "recommended_actions": [
            {"name": "gateway.apikey.revoke", "args": {"principal": offender}},
            {"name": "gateway.profile.tighten", "args": {"agent": offender, "allow": ["echo"]}},
        ],
    }
    with open(OUT, "w") as f:
        json.dump(scenario, f, indent=2)
    print("wrote", OUT)
    print("  event mix        :", dict(kinds))
    print("  offender         :", offender, off_ip)
    print("  attacker IP      :", attacker_ip or "(none)")
    print("\nNow run:  aisoc-sandbox demo --file", OUT)


if __name__ == "__main__":
    main()
