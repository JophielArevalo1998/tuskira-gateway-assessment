#!/usr/bin/env python3
# LLM resource abuse vs the gateway's LLM-plane governance; zero paid spend (mock upstream).
import json,os,sys,time,urllib.request,urllib.error
API=os.environ.get("GATEWAY_API","http://localhost:8081/api/v1"); LLM="http://localhost:8082"
ADMIN=os.environ["GATEWAY_ADMIN_KEY"]; MODEL="mock-chat"; AIP="203.0.113.90"; GIP="198.51.100.21"
def req(url,method="GET",key=None,xff=None,body=None,gw=False):
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,data=d,method=method); r.add_header("Content-Type","application/json")
    if key: r.add_header("X-Gateway-Key" if gw else "Authorization", key if gw else "Bearer "+key)
    if xff: r.add_header("X-Forwarded-For",xff)
    try:
        with urllib.request.urlopen(r,timeout=20) as x: return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code,e.read().decode("utf-8","replace")
    except Exception as e: return 0,str(e)
def api(m,p,b=None): return req(API+p,method=m,key=ADMIN,body=b)
def ensure_model():
    _,b=api("GET","/models?limit=500")
    try:
        it=json.loads(b); it=it.get("items",it) if isinstance(it,dict) else it
        for m in it:
            if m.get("name")==MODEL: return
    except Exception: pass
    s,b=api("POST","/models",{"name":MODEL,"description":"local mock, $0","targets":[{"vendor":"openai_compat","model":"mock-1","base_url":"http://host.docker.internal:8099/v1","allow_caller_key":True,"label":"mock"}],"price":{"input":3,"output":15}})
    if s not in (200,201): sys.exit("model register failed: %s %s"%(s,b[:300]))
def mint(name,limits=None):
    b={"name":name,"role":"agent"}; b.update({"limits":limits} if limits else {})
    s,r=api("POST","/api-keys",b)
    if s not in (200,201): sys.exit("mint failed: %s %s"%(s,r[:300]))
    j=json.loads(r); return j["key"],j["id"]
def chat(key,xff,msg,mt):
    s,b=req(LLM+"/openai/v1/chat/completions",method="POST",key=key,xff=xff,gw=True,
        body={"model":MODEL,"max_tokens":mt,"stream":False,"messages":[{"role":"user","content":msg}]})
    try:
        j=json.loads(b)
        if s==200 and j.get("choices"): return 200,""
        return s,(j.get("error") or {}).get("message","")
    except Exception: return s,b[:120]
def kind(s,why):
    w=why.lower()
    if s==200: return "ok"
    if "max_tokens" in w or "exceeds" in w: return "max_tokens"
    if "budget" in w: return "budget"
    if "rpm" in w or "per minute" in w or "rate limit" in w: return "rpm"
    return "other"
ensure_model()
good,_=mint("gen-llm-agent"); ab,abid=mint("gen-llm-abuser",{"rpm":6,"max_tokens":2048})
c={"ok":0,"max_tokens":0,"rpm":0,"budget":0,"other":0}
print("[baseline] 10 good LLM calls ...")
for i in range(10): c[kind(*chat(good,GIP,"summarize ticket %d"%i,256))]+=1; time.sleep(0.1)
print("[A] oversized generation (max_tokens=60000) ..."); c[kind(*chat(ab,AIP,"write an essay",60000))]+=1
print("[B] rate burst (18 calls, rpm cap 6) ...")
for i in range(18): c[kind(*chat(ab,AIP,"spin %d"%i,256))]+=1
print("[C] budget burn: daily_usd=$0.03, wait, then call ...")
api("PATCH","/api-keys/%s"%abid,{"limits":{"daily_usd":0.03}}); time.sleep(11)
for i in range(12): c[kind(*chat(ab,AIP,"report section %d"%i,256))]+=1; time.sleep(0.4)
print("\n=== generated ===")
for k in ("ok","max_tokens","rpm","budget","other"): print("  %-10s %d"%(k,c[k]))
print("  OFFENDER key id:",abid,"(gen-llm-abuser)")
print("\nConsole: Overview tiles + LLM Logs (filter gen-llm-abuser). Then: python3 adapt_llm.py")
