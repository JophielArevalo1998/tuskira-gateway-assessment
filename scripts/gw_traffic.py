#!/usr/bin/env python3
"""Example 1 - drive a believable mix of AI-agent traffic through a local
Tuskira gateway, so the console dashboard and the exported feed tell a real
SOC story: a baseline of well-behaved agents, a compromised agent probing
off-profile tools and spiking volume, and a credential brute force from one IP.

It uses X-Forwarded-For to give each simulated actor its own source IP
(the shipped compose trusts XFF from the docker bridge), which keeps the
brute-force lockout on the attacker's IP instead of the whole demo.

Prereqs: the gateway up, the "everything" connector registered + its npx
server running, and GATEWAY_ADMIN_KEY exported. Pure stdlib.

  export GATEWAY_ADMIN_KEY=gk_...
  python3 gw_traffic.py --baseline 12 --probes 10 --spike 60 --bruteforce 16
  python3 gw_traffic.py --dry-run
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

API = os.environ.get("GATEWAY_API", "http://localhost:8081/api/v1")
MCP = os.environ.get("GATEWAY_MCP", "http://localhost:8080/mcp")
ADMIN = os.environ.get("GATEWAY_ADMIN_KEY", "")

GOOD_IPS = {"analyst-bot": "198.51.100.11", "summarizer": "198.51.100.12", "indexer": "198.51.100.13"}
COMPROMISED_IP = "203.0.113.77"
ATTACKER_IP = "203.0.113.200"
DRY = False


def _req(url, method="GET", key=None, xff=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    r.add_header("Accept", "application/json, text/event-stream")
    if key:
        r.add_header("Authorization", "Bearer " + key)
    if xff:
        r.add_header("X-Forwarded-For", xff)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, {}, str(e)


def api(method, path, body=None):
    return _req(API + path, method=method, key=ADMIN, body=body)


def ensure_connector():
    _, _, b = api("GET", "/connectors?limit=500")
    try:
        for it in json.loads(b).get("items", []):
            if it.get("slug") == "everything":
                return it["id"]
    except Exception:
        pass
    sys.exit("no 'everything' connector found - register it (examples/01-quickstart) and keep the npx server running")


def ensure_profile(name, connector_id, tools):
    _, _, b = api("GET", "/profiles?limit=500")
    pid = None
    try:
        for it in json.loads(b).get("items", []):
            if it.get("name") == name:
                pid = it["id"]
                break
    except Exception:
        pass
    if pid is None:
        _, _, b = api("POST", "/profiles", {"name": name})
        pid = json.loads(b)["id"]
    if tools is not None:
        api("PUT", "/profiles/%s/tools" % pid, {"tools": [{"connector_id": connector_id, "tool_name": t} for t in tools]})
    return pid


def mint_key(name):
    _, _, b = api("POST", "/api-keys", {"name": name, "role": "agent"})
    return json.loads(b)["key"]


def mcp_init(key, xff):
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "traffic-gen", "version": "0.1.0"}}}
    status, headers, _ = _req(MCP, method="POST", key=key, xff=xff, body=body)
    sid = headers.get("Mcp-Session-Id") if hasattr(headers, "get") else None
    return status, sid


def mcp_call(key, sid, xff, profile, tool, args):
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": args}}
    r = urllib.request.Request(MCP, data=json.dumps(body).encode(), method="POST")
    r.add_header("Content-Type", "application/json")
    r.add_header("Accept", "application/json, text/event-stream")
    r.add_header("Authorization", "Bearer " + key)
    r.add_header("X-Forwarded-For", xff)
    r.add_header("Mcp-Session-Id", sid or "")
    if profile:
        r.add_header("X-Agent-Profile-Name", profile)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, str(e)


def main():
    global DRY
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=int, default=12, help="normal calls per good agent")
    ap.add_argument("--probes", type=int, default=10, help="off-profile denials from the compromised agent")
    ap.add_argument("--spike", type=int, default=60, help="rapid calls in the volume spike")
    ap.add_argument("--bruteforce", type=int, default=16, help="bad-key attempts from the attacker IP")
    ap.add_argument("--pace", type=float, default=0.15, help="seconds between normal calls")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    DRY = a.dry_run

    plan = [
        ("baseline", "%d good agents x %d allowed echo calls (no profile = full access), each from its own IP" % (len(GOOD_IPS), a.baseline)),
        ("probes", "compromised agent probes get-env x %d under 'Echo Only' -> -32003 denials" % a.probes),
        ("spike", "compromised agent fires %d rapid echo calls -> volume anomaly" % a.spike),
        ("bruteforce", "attacker IP sends %d bad-key inits -> 401s then a 429 lockout" % a.bruteforce),
    ]
    print("=== traffic plan ===")
    for n, d in plan:
        print("  %-11s %s" % (n, d))
    if DRY:
        print("\n(dry run - nothing sent)")
        return
    if not ADMIN:
        sys.exit("set GATEWAY_ADMIN_KEY first")

    cid = ensure_connector()
    ensure_profile("Echo Only", cid, ["echo", "get-sum"])  # the compromised agent is scoped to this
    good_keys = {name: mint_key("gen-" + name) for name in GOOD_IPS}
    comp_key = mint_key("gen-compromised")
    counts = {"ok": 0, "denied": 0, "401": 0, "429": 0, "err": 0}

    print("\n[1/4] baseline traffic ...")
    for name, ip in GOOD_IPS.items():
        _, sid = mcp_init(good_keys[name], ip)
        for i in range(a.baseline):
            st, body = mcp_call(good_keys[name], sid, ip, None, "everything__echo", {"message": "%s task %d" % (name, i)})
            counts["ok" if st == 200 and '"error"' not in body else "err"] += 1
            time.sleep(a.pace)

    print("[2/4] off-profile probing (compromised agent) ...")
    _, csid = mcp_init(comp_key, COMPROMISED_IP)
    for i in range(a.probes):
        st, body = mcp_call(comp_key, csid, COMPROMISED_IP, "Echo Only", "everything__get-env", {})
        counts["denied" if "-32003" in body else "err"] += 1
        time.sleep(a.pace)

    print("[3/4] volume spike (compromised agent) ...")
    for i in range(a.spike):
        st, body = mcp_call(comp_key, csid, COMPROMISED_IP, "Echo Only", "everything__echo", {"message": "spike %d" % i})
        counts["ok" if st == 200 and '"error"' not in body else "err"] += 1

    print("[4/4] credential brute force (attacker IP) ...")
    for i in range(a.bruteforce):
        st, _ = mcp_init("gk_not_a_real_key_%d" % i, ATTACKER_IP)
        if st == 401:
            counts["401"] += 1
        elif st == 429:
            counts["429"] += 1
        else:
            counts["err"] += 1
        time.sleep(0.05)

    print("\n=== generated ===")
    print("  allowed calls : %d" % counts["ok"])
    print("  denied (-32003): %d" % counts["denied"])
    print("  401 auth fail : %d" % counts["401"])
    print("  429 lockout   : %d" % counts["429"])
    print("  errors        : %d" % counts["err"])
    print("\nConsole (http://localhost:8081): Overview, Access Logs, Top Agents.")
    print("Then build the AiSOC scenario:  python3 adapt.py")


if __name__ == "__main__":
    main()
