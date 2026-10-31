#!/usr/bin/env python3
"""The bridge — a continuous, live detect-and-respond loop between the Tuskira
AI Agent Gateway and AiSOC.

It tails the gateway's telemetry feed, runs detectors over a rolling window,
and on each new incident:
  1. builds an AiSOC scenario and runs the AiSOC sandbox to get an
     investigation ledger (the "brain"),
  2. decides containment under a blast-radius policy gate, and
  3. executes it against the gateway's control-plane API (the "hands"),
     writing every action to an audit log.

This replaces the bench's batch `ship.sh -> adapt.py -> aisoc-sandbox --file`
with an always-on loop. Pure Python standard library (+ the `aisoc-sandbox`
CLI if you want the ledgers; optional).

Feed: one JSON record per line, as the gateway emits to stdout —
  {"type":"access"|"llm_call","record":{...}}
Populate it live from kind with (the live version of ship.sh):
  kubectl logs -f -n ai-gateway -l app.kubernetes.io/part-of=gateway \
    --all-containers --max-log-requests 12 \
    | grep --line-buffered '"record":' >> ~/bench/live-feed.jsonl

Config (env):
  GW_API           gateway control-plane API   (default http://localhost:28081/api/v1)
  GW_RESPONDER_KEY admin key the responder uses to execute containment  (required unless DRY_RUN)
  FEED             telemetry feed file         (default ~/bench/live-feed.jsonl)
  STATE_DIR        incidents/audit/pending     (default ~/bench/bridge-state)
  AISOC_CMD        how to run the sandbox      (default "aisoc-sandbox demo --file {file}"; "" to skip)
  AUTO_TIERS       tiers that auto-execute     (default "low"; else queued for approval)
  WINDOW_SEC       rolling detection window    (default 300)
  COOLDOWN_SEC     per-incident cooldown       (default 600)
  ENUM_THRESHOLD   distinct denied tools = enum(default 6)
  POLL_SEC         loop interval               (default 3)
  DRY_RUN          1 = detect + propose, never execute  (default 0)
"""
import base64
import json
import os
import subprocess
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone

GW_API = os.environ.get("GW_API", "http://localhost:28081/api/v1")
RESPONDER_KEY = os.environ.get("GW_RESPONDER_KEY", "")
FEED = os.path.expanduser(os.environ.get("FEED", "~/bench/live-feed.jsonl"))
STATE_DIR = os.path.expanduser(os.environ.get("STATE_DIR", "~/bench/bridge-state"))
AISOC_CMD = os.environ.get("AISOC_CMD", "aisoc-sandbox demo --file {file}")
AUTO_TIERS = set(t.strip() for t in os.environ.get("AUTO_TIERS", "low").split(",") if t.strip())
WINDOW = int(os.environ.get("WINDOW_SEC", "300"))
COOLDOWN = int(os.environ.get("COOLDOWN_SEC", "600"))
ENUM_THRESHOLD = int(os.environ.get("ENUM_THRESHOLD", "6"))
POLL = float(os.environ.get("POLL_SEC", "3"))
DRY_RUN = os.environ.get("DRY_RUN", "0") not in ("0", "", "false", "False")

INJECTION_INDICATORS = [
    "ignore all previous", "ignore previous instructions", "system prompt",
    "system override", "you are now dan", "disable all", "exfil",
    "/etc/shadow", "attacker.example", "evil.example", "delete the audit",
    "reveal your", "jailbreak",
]


def log(*a):
    print(datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def parse_ts(s):
    if not s:
        return time.time()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return time.time()


def body_text(rec):
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


# ---------------- gateway control-plane (the hands) ----------------
def gw(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(GW_API + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    r.add_header("Authorization", "Bearer " + RESPONDER_KEY)
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, str(e)


def execute(action):
    """Run one containment action against the gateway. Returns (ok, detail)."""
    name, args = action["name"], action.get("args", {})
    if DRY_RUN:
        return True, "DRY_RUN (not executed)"
    if name == "revoke_key":
        st, b = gw("DELETE", "/api-keys/%s" % args["key_id"])
        return st in (200, 204), "HTTP %s" % st
    if name == "tighten_limits":
        st, b = gw("PATCH", "/api-keys/%s" % args["key_id"], {"limits": args.get("limits", {"rpm": 0})})
        return st == 200, "HTTP %s" % st
    return False, "unknown action %s" % name


# ---------------- AiSOC (the brain) ----------------
def run_aisoc(scenario, incident_id):
    """Write the scenario, run the AiSOC sandbox, capture the ledger. Optional."""
    if not AISOC_CMD.strip():
        return None
    sfile = os.path.join(STATE_DIR, "incidents", incident_id + ".scenario.json")
    with open(sfile, "w") as f:
        json.dump(scenario, f, indent=2)
    try:
        cmd = AISOC_CMD.format(file=sfile)
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        ledger = out.stdout + ("\n" + out.stderr if out.stderr else "")
    except Exception as e:  # noqa
        ledger = "aisoc invocation failed: %s" % e
    lfile = os.path.join(STATE_DIR, "incidents", incident_id + ".ledger.txt")
    with open(lfile, "w") as f:
        f.write(ledger)
    return lfile


# ---------------- detectors (the eyes) ----------------
def detect(window):
    """Return a list of incidents {type, offender, offender_ip, key_id, severity,
    mitre, action, tier, scenario}. Window = list of parsed records."""
    acc = [e for e in window if e["t"] == "access"]
    llm = [e for e in window if e["t"] == "llm_call"]
    incidents = []

    # 1. tool enumeration (one principal, many distinct denied tools)
    enum = defaultdict(set); enum_ip = {}; enum_key = {}
    for e in acc:
        r = e["r"]
        if str(r.get("error_code")) == "-32003":
            p = r.get("principal") or r.get("key_id") or "?"
            enum[p].add(r.get("tool_name") or "?")
            enum_ip[p] = r.get("client_ip") or ""
            enum_key[p] = r.get("key_id") or ""
    for p, tools in enum.items():
        if len(tools) >= ENUM_THRESHOLD and enum_key.get(p):
            incidents.append(_incident(
                "tool_enumeration", p, enum_ip[p], enum_key[p], "high",
                ["T1613", "T1069"],
                "%d distinct off-profile tools probed" % len(tools),
                {"name": "revoke_key", "args": {"key_id": enum_key[p]}}, "low",
                _events(acc, lambda r: r.get("principal") == p and str(r.get("error_code")) == "-32003")))
        elif enum_key.get(p):  # a single off-profile slip, not enumeration
            pass

    # 2. compromised agent (off-profile denials below the enum bar + any spike)
    deny = Counter(); d_ip = {}; d_key = {}
    for e in acc:
        r = e["r"]
        if str(r.get("error_code")) == "-32003":
            p = r.get("principal") or r.get("key_id") or "?"
            deny[p] += 1; d_ip[p] = r.get("client_ip") or ""; d_key[p] = r.get("key_id") or ""
    for p, n in deny.items():
        if n >= 3 and len(enum.get(p, set())) < ENUM_THRESHOLD and d_key.get(p):
            incidents.append(_incident(
                "compromised_agent", p, d_ip[p], d_key[p], "high",
                ["T1069", "T1078"], "%d off-profile denials" % n,
                {"name": "revoke_key", "args": {"key_id": d_key[p]}}, "low",
                _events(acc, lambda r, _p=p: r.get("principal") == _p and str(r.get("error_code")) == "-32003")))

    # 3. credential brute force (one IP, many auth failures / a lockout)
    bf = Counter()
    for e in acc + llm:
        r = e["r"]; ip = r.get("client_ip") or ""; sc = r.get("status_code")
        if not ip:
            continue
        # auth failures (either plane) or MCP-plane lockout; NOT LLM governance 429s
        if sc == 401 or (e["t"] == "access" and sc == 429):
            bf[ip] += 1
    for ip, n in bf.items():
        if n >= 6:
            incidents.append(_incident(
                "brute_force", ip, ip, "", "high", ["T1110"],
                "%d auth failures / lockouts from one IP" % n, None, "info",
                _events(acc + llm, lambda r: r.get("client_ip") == ip and r.get("status_code") in (401, 429))))

    # 4. LLM resource abuse (one key, governance denials)
    llm_den = defaultdict(Counter); l_ip = {}
    for e in llm:
        r = e["r"]; err = (r.get("error") or "").lower(); key = r.get("key_id") or r.get("principal") or "?"
        if r.get("status_code") == 200:
            continue
        kind = ("max_tokens" if ("max_tokens" in err or "exceeds" in err) else
                "budget" if "budget" in err else
                "rpm" if ("rpm" in err or "per minute" in err or "rate limit" in err) else None)
        if kind:
            llm_den[key][kind] += 1; l_ip[key] = r.get("client_ip") or ""
    for key, d in llm_den.items():
        if sum(d.values()) >= 5 and key != "?":
            incidents.append(_incident(
                "llm_abuse", key, l_ip[key], key, "high",
                ["AML.T0034", "T1496"],
                "%d LLM governance denials (max_tokens=%d rpm=%d budget=%d)" % (
                    sum(d.values()), d["max_tokens"], d["rpm"], d["budget"]),
                {"name": "revoke_key", "args": {"key_id": key}}, "low",
                _events(llm, lambda r: (r.get("key_id") or r.get("principal")) == key and r.get("status_code") != 200)))

    # 5. prompt injection (allowed tool call carrying a hostile payload).
    # Response is a REVOKE, not a throttle: the gateway enforces a key's rpm
    # only on the LLM plane, so tighten_limits(rpm:0) can't contain an
    # MCP-borne injection -- revoking the key fails it at auth on every plane.
    inj = defaultdict(list); i_ip = {}; i_key = {}
    for e in acc:
        r = e["r"]
        if r.get("method") != "tools/call":
            continue
        if any(k in body_text(r).lower() for k in INJECTION_INDICATORS):
            p = r.get("principal") or r.get("key_id") or "?"
            inj[p].append(r); i_ip[p] = r.get("client_ip") or ""; i_key[p] = r.get("key_id") or ""
    for p, rows in inj.items():
        if i_key.get(p):
            incidents.append(_incident(
                "prompt_injection", p, i_ip[p], i_key[p], "high",
                ["AML.T0051", "AML.T0054"], "%d injection payloads forwarded" % len(rows),
                {"name": "revoke_key", "args": {"key_id": i_key[p]}}, "low",
                [{"uuid": r.get("request_id") or "", "eventType": "mcp.tool.call.suspicious_input",
                  "actor": p, "client_ip": i_ip[p]} for r in rows]))
    return incidents


def _events(rows, pred):
    return [{"uuid": e["r"].get("request_id") or "", "eventType": e["r"].get("method") or "event",
             "actor": e["r"].get("principal") or e["r"].get("key_id") or "?",
             "client_ip": e["r"].get("client_ip") or ""} for e in rows if pred(e["r"])][:25]


def _incident(typ, offender, ip, key_id, sev, mitre, summary, action, tier, events):
    return {"type": typ, "offender": offender, "offender_ip": ip, "key_id": key_id,
            "severity": sev, "mitre": mitre, "summary": summary, "action": action,
            "tier": tier, "events": events}


def to_scenario(inc, iid):
    return {"id": iid, "title": inc["type"].replace("_", " ").title(),
            "narrative": "%s. offender=%s ip=%s. %s" % (inc["type"], inc["offender"], inc["offender_ip"], inc["summary"]),
            "severity": inc["severity"], "mitre_techniques": inc["mitre"],
            "entities": {"user": inc["offender"], "ip_a": inc["offender_ip"], "ip_b": "",
                         "asset": "AI Agent Gateway"},
            "events": inc["events"],
            "recommended_actions": [{"name": "gateway." + (inc["action"]["name"] if inc["action"] else "monitor"),
                                     "args": inc["action"]["args"] if inc["action"] else {}}]}


# ---------------- main loop ----------------
def main():
    for d in ("incidents", "pending"):
        os.makedirs(os.path.join(STATE_DIR, d), exist_ok=True)
    audit = open(os.path.join(STATE_DIR, "audit.log"), "a")

    def record(msg):
        line = datetime.now(timezone.utc).isoformat() + " " + msg
        audit.write(line + "\n"); audit.flush(); log(msg)

    log("bridge up | api=%s | auto=%s | dry_run=%s | feed=%s" % (GW_API, sorted(AUTO_TIERS), DRY_RUN, FEED))
    if not RESPONDER_KEY and not DRY_RUN:
        log("WARNING: GW_RESPONDER_KEY not set; running as if DRY_RUN")
    window = deque()
    seen = {}   # incident key -> last-fired epoch (cooldown)
    offset = 0
    last_detect = 0

    while True:
        # follow the feed file
        try:
            size = os.path.getsize(FEED) if os.path.exists(FEED) else 0
            if size < offset:
                offset = 0  # file truncated/rotated
            if size > offset:
                with open(FEED, "r", errors="replace") as fh:
                    fh.seek(offset)
                    while True:
                        ln = fh.readline()
                        if not ln or not ln.endswith("\n"):
                            break  # EOF or a partial (still-being-written) line
                        offset = fh.tell()
                        s = ln.strip()
                        if not s:
                            continue
                        try:
                            o = json.loads(s)
                        except Exception:
                            continue
                        r = o.get("record") or {}
                        window.append({"t": o.get("type"), "r": r, "ts": parse_ts(r.get("timestamp"))})
        except Exception as e:  # noqa
            log("feed read error:", e)

        # prune the window
        cutoff = time.time() - WINDOW
        while window and window[0]["ts"] < cutoff:
            window.popleft()

        # detect on an interval
        now = time.time()
        if now - last_detect >= POLL:
            last_detect = now
            for inc in detect(list(window)):
                key = (inc["type"], inc["offender"])
                if now - seen.get(key, 0) < COOLDOWN:
                    continue
                seen[key] = now
                iid = "%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), inc["type"])
                record("INCIDENT %s | %s | offender=%s ip=%s | %s" % (
                    iid, inc["type"], inc["offender"], inc["offender_ip"], inc["summary"]))
                # brain: investigation ledger
                ledger = run_aisoc(to_scenario(inc, iid), iid)
                if ledger:
                    record("  investigation -> %s" % ledger)
                # hands: containment under the policy gate
                if not inc["action"]:
                    record("  no auto action (type=%s) -- analyst review" % inc["type"])
                    continue
                if inc["tier"] in AUTO_TIERS:
                    ok, detail = execute(inc["action"])
                    record("  EXECUTED %s on %s -> %s (%s)" % (
                        inc["action"]["name"], inc["action"]["args"].get("key_id", "?"),
                        "ok" if ok else "FAILED", detail))
                else:
                    pfile = os.path.join(STATE_DIR, "pending", iid + ".json")
                    with open(pfile, "w") as f:
                        json.dump({"incident": inc, "action": inc["action"]}, f, indent=2)
                    record("  QUEUED for approval (tier=%s) -> %s" % (inc["tier"], pfile))
        time.sleep(min(POLL, 2))


if __name__ == "__main__":
    main()
