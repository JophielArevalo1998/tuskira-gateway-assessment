"""brute_attack.py -- credential brute force against the gateway's auth.

Sprays invalid API keys at the MCP plane from one IP. The gateway's
auth-failure limiter locks the IP out after 10 failures within a minute:
the first ten get 401, the rest get 429 + Retry-After (a 5-minute lockout).

The gateway defends ITSELF here -- and that is the finding. These 401s and
429s are rejected at the auth layer, BEFORE the data plane, so they never
reach the telemetry feed. The bridge's brute_force detector therefore sees
nothing (it can't) and takes no action; the gateway's own lockout is the only
thing that stopped the attack. (Reinforces finding G1: auth rejections are
invisible to the telemetry.)

Targets the MCP plane on purpose: the lockout is per-plane and per-IP, so it
locks 127.0.0.1 out of MCP for 5 minutes without touching the API plane, the
bridge, or admin access.

Env: GATEWAY_MCP (:28080).
"""
import os, time, urllib.request, urllib.error

MCP = os.environ.get("GATEWAY_MCP", "http://localhost:8080/mcp")
IP = "203.0.113.150"
N = 14


def spray(badkey):
    r = urllib.request.Request(MCP, data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', method="POST")
    for k, v in [("Content-Type", "application/json"),
                 ("Accept", "application/json, text/event-stream"),
                 ("Authorization", "Bearer " + badkey), ("X-Forwarded-For", IP)]:
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=10) as x:
            return x.status, x.headers.get("Retry-After")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Retry-After")
    except Exception as e:  # noqa
        return 0, str(e)


print("spraying %d invalid API keys at the MCP plane from one IP...\n" % N)
locked_at = None
for i in range(1, N + 1):
    st, ra = spray("gk_fake%02d%d" % (i, int(time.time())))
    if st == 429:
        locked_at = locked_at or i
        print("  attempt %2d -> 429 LOCKED OUT (Retry-After: %ss)" % (i, ra))
    elif st == 401:
        print("  attempt %2d -> 401 unauthorized" % i)
    else:
        print("  attempt %2d -> status=%s" % (i, st))
    time.sleep(0.3)

if locked_at:
    print("\n** IP locked out from attempt %d -- the gateway stopped the brute force itself. **" % locked_at)
else:
    print("\n(no lockout seen -- raise N; the limiter trips at 10 failures within a minute)")

print("\nNow check the BRIDGE terminal: it shows NOTHING for this attack.")
print("Those 401s and 429s are rejected at the auth layer, before the data plane,")
print("so they never reach the telemetry feed -- the bridge is blind to them (finding G1).")
