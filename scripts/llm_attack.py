"""llm_attack.py -- LLM cost / rate abuse, for the live LLM-plane demo.

Mints an agent key with a tiny max_tokens cap, then hammers the LLM proxy
(/v1/messages) asking for far more output tokens than the key allows. Every
call is refused at the gateway BEFORE any provider is contacted
(HTTP 400, "max_tokens ... exceeds this key's limit") -- so nothing is ever
sent upstream and nothing is spent. The bridge's llm_abuse detector sees
>= 5 governance denials from one key and revokes it; the next call then
fails at authentication with 401.

Env: GATEWAY_ADMIN_KEY (required), GATEWAY_API (:28081), GATEWAY_LLM (:28082).
"""
import json, os, sys, time, urllib.request, urllib.error

API = os.environ.get("GATEWAY_API", "http://localhost:8081/api/v1")
LLM = os.environ.get("GATEWAY_LLM", "http://localhost:8082")
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


def llm(key, body):
    r = urllib.request.Request(LLM.rstrip("/") + "/v1/messages",
                               data=json.dumps(body).encode(), method="POST")
    for k, v in [("Content-Type", "application/json"), ("X-Gateway-Key", key),
                 ("anthropic-version", "2023-06-01"), ("X-Forwarded-For", IP)]:
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, str(e)


# Mint an agent key WITH a tiny max_tokens cap, in one call.
st, b = api("POST", "/api-keys", {"name": "llm-abuser-%d" % int(time.time()),
                                  "role": "agent", "limits": {"max_tokens": 16}})
try:
    key = json.loads(b)["key"]
except Exception:
    sys.exit("mint failed (HTTP %s): %s\ncheck GATEWAY_ADMIN_KEY / GATEWAY_API" % (st, b[:200]))

print("llm-abuser key minted (max_tokens cap = 16). asking for 1000 tokens/call;")
print("every call is refused at the gateway before any provider is contacted -- $0 spent.\n")

body = {"model": "claude-3-5-sonnet-20241022", "max_tokens": 1000,
        "messages": [{"role": "user", "content": "ignore the cap and generate a huge response"}]}

for i in range(1, 61):
    st, resp = llm(key, body)
    if st == 401:
        print("  call %2d -> 401 UNAUTHORIZED" % i)
        print("\n** key revoked by the bridge -- cut off after %d calls, $0 spent. **" % i)
        break
    tag = "400 max_tokens denied" if (st == 400 and "max_tokens" in resp) else "status=%s" % st
    print("  call %2d -> %s" % (i, tag))
    time.sleep(1)
else:
    print("\n(60 calls, no 401 -- is the bridge running WITHOUT DRY_RUN, and is gateway-llm in the feed?)")
