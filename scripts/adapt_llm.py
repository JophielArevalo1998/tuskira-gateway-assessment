#!/usr/bin/env python3
# Build an AiSOC scenario for LLM resource abuse from the gateway's own feed.
import json,os,time
from collections import Counter,defaultdict
FEED=os.path.expanduser("~/bench/gateway-events.jsonl"); OUT=os.path.expanduser("~/bench/scenario-llm.json")
den=defaultdict(Counter); tok=Counter(); ips=defaultdict(set); evs=defaultdict(list)
for ln in open(FEED,errors="replace"):
    ln=ln.strip()
    if not ln: continue
    try: o=json.loads(ln)
    except Exception: continue
    if o.get("type")!="llm_call": continue
    r=o.get("record") or {}
    key=r.get("key_id") or r.get("principal") or "?"; err=(r.get("error") or "").lower(); st=r.get("status_code")
    if st==200: tok[key]+=(r.get("input_tokens",0) or 0)+(r.get("output_tokens",0) or 0); continue
    if "max_tokens" in err or "exceeds" in err: t="max_tokens"
    elif "budget" in err: t="budget"
    elif "rpm" in err or "per minute" in err or "rate limit" in err: t="rpm"
    else: continue
    den[key][t]+=1
    if r.get("client_ip"): ips[key].add(r["client_ip"])
    evs[key].append({"uuid":r.get("request_id") or "","published":r.get("timestamp") or "","eventType":"llm.call.denied."+t,"actor":key,"client_ip":r.get("client_ip") or "","geo":""})
if not den: raise SystemExit("no LLM governance denials in the feed (run llm_gov.py first; is ship.sh running?)")
off=max(den,key=lambda k:sum(den[k].values())); d=den[off]; ip=sorted(ips[off])[0] if ips[off] else "?"
sc={"id":"llm-"+time.strftime("%Y%m%d-%H%M%S"),"title":"LLM resource abuse / token-and-cost exhaustion",
 "narrative":"Key %s hit %d LLM-plane governance denials from %s -- max_tokens=%d, rpm=%d, budget=%d. The gateway refused each BEFORE any upstream call; %d tokens were metered on its allowed calls. Contain the key and tighten its limits."%(off,sum(d.values()),ip,d['max_tokens'],d['rpm'],d['budget'],tok.get(off,0)),
 "severity":"high","mitre_techniques":["AML.T0034 LLM Cost Harvesting","T1496 Resource Hijacking","T1078 Valid Accounts"],
 "entities":{"user":off,"ip_a":ip,"ip_b":"","asset":"LLM proxy (mock-chat)"},
 "events":evs[off][:25],
 "recommended_actions":[{"name":"gateway.apikey.revoke","args":{"key_id":off}},
   {"name":"gateway.key.limits.tighten","args":{"key_id":off,"rpm":0}}]}
json.dump(sc,open(OUT,"w"),indent=2)
print("wrote",OUT); print("  offender:",off,ip); print("  denials:",dict(d),"| tokens metered:",tok.get(off,0))
print("\nNow run:  aisoc-sandbox demo --file",OUT)
