"""live_attack.py -- a persistent compromised agent, for the live loop demo.

Mints an agent key scoped to the 'Echo Only' profile, then hammers one
off-profile tool once a second. Each call is DENIED (-32003) while the key is
alive; the moment the bridge revokes the key, the very next call comes back
401 and the attacker is cut off. Run this (terminal 2) while bridge.py runs
WITHOUT DRY_RUN (terminal 1) and watch the loop close itself.

Env: GATEWAY_ADMIN_KEY (required), GATEWAY_API, GATEWAY_MCP (kind: :28081/:28080).
"""
import json, os, sys, time, urllib.request, urllib.error

API = os.environ.get("GATEWAY_API", "http://localhost:8081/api/v1")
MCP = os.environ.get("GATEWAY_MCP", "http://localhost:8080/mcp")
ADMIN = os.environ["GATEWAY_ADMIN_KEY"]
IP = "203.0.113.150"


def api(m, p, b=None):
    d = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(API + p, data=d, method=m)
    r.add_header("Content-Type", "application/json")
    r.add_header("Authorization", "Bearer " + ADMIN)
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, str(e)


def cid():
    _, b = api("GET", "/connectors?limit=500")
    for it in json.loads(b).get("items", []):
        if it.get("slug") == "everything":
            return it["id"]
    sys.exit("no 'everything' connector -- run examples/10-kubernetes/run.sh first")


def profile(name, c, tools):
    _, b = api("GET", "/profiles?limit=500")
    pid = None
    for it in json.loads(b).get("items", []):
        if it.get("name") == name:
            pid = it["id"]; break
    if pid is None:
        _, b = api("POST", "/profiles", {"name": name}); pid = json.loads(b)["id"]
    api("PUT", "/profiles/%s/tools" % pid, {"tools": [{"connector_id": c, "tool_name": t} for t in tools]})
    return pid


def mint(name):
    _, b = api("POST", "/api-keys", {"name": name, "role": "agent"})
    return json.loads(b)["key"]


def mcp(key, body, sid=None):
    r = urllib.request.Request(MCP, data=json.dumps(body).encode(), method="POST")
    for k, v in [("Content-Type", "application/json"),
                 ("Accept", "application/json, text/event-stream"),
                 ("Authorization", "Bearer " + key), ("X-Forwarded-For", IP)]:
        r.add_header(k, v)
    if sid:
        r.add_header("Mcp-Session-Id", sid)
    if body.get("method") == "tools/call":
        r.add_header("X-Agent-Profile-Name", "Echo Only")
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return x.status, x.headers.get("Mcp-Session-Id"), x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, None, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, None, str(e)


c = cid()
profile("Echo Only", c, ["echo", "get-sum"])
key = mint("live-attacker-%d" % int(time.time()))
st, sid, _ = mcp(key, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "attacker", "version": "0.1"}}})
print("attacker key minted (session=%s). hammering an off-profile tool once/sec;" % (sid or "?"))
print("the bridge should detect and revoke us within a few calls...\n")
for i in range(1, 61):
    st, _, b = mcp(key, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "everything__list-secrets", "arguments": {}}}, sid)
    if st == 401:
        print("  call %2d -> 401 UNAUTHORIZED" % i)
        print("\n** key revoked by the bridge -- cut off after %d calls. the loop closed itself. **" % i)
        break
    tag = "200 / denied -32003" if "-32003" in b else "status=%s" % st
    print("  call %2d -> %s" % (i, tag))
    time.sleep(1)
else:
    print("\n(60 calls, no 401 -- is the bridge running WITHOUT DRY_RUN, and is the feed live?)")
