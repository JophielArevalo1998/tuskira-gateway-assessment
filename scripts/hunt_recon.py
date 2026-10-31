import json,os
from collections import defaultdict
FEED=os.path.expanduser("~/bench/gateway-events.jsonl")
by=defaultdict(set); ips=defaultdict(set)
for ln in open(FEED,errors="replace"):
    ln=ln.strip()
    if not ln: continue
    try: o=json.loads(ln)
    except Exception: continue
    if o.get("type")!="access": continue
    r=o.get("record") or {}
    if str(r.get("error_code"))!="-32003": continue
    p=r.get("principal") or r.get("key_id") or "?"
    by[p].add(r.get("tool_name") or "?")
    if r.get("client_ip"): ips[p].add(r["client_ip"])
print("HUNT H-1  tool enumeration / permission discovery")
print("Hypothesis: one identity probing many tools it isn't granted (distinct denied tools, not call count).\n")
if not by: raise SystemExit("no -32003 denials in the feed (run tool_recon.py; is ship.sh running?)")
for p,t in sorted(by.items(),key=lambda kv:len(kv[1]),reverse=True):
    flag="  <-- ENUMERATION" if len(t)>=6 else ""
    print("  principal %s"%p); print("     distinct tools denied: %d%s"%(len(t),flag))
    print("     from IP: %s"%", ".join(sorted(ips[p]))); print("     tools: %s"%", ".join(sorted(t)))
top,tools=max(by.items(),key=lambda kv:len(kv[1]))
if len(tools)>=6:
    print("\nVERDICT: confirmed. %s enumerated %d distinct tools -> tighten/rotate the key via the gateway API."%(top,len(tools)))
