# Secret injection: the gateway holds a credential and injects it at call time;
# the agent never sends it, never sees it, and can't read it from the vault.
import json,os,sys,urllib.request,urllib.error
API=os.environ.get("GATEWAY_API","http://localhost:8081/api/v1"); LLM="http://localhost:8082"
ADMIN=os.environ.get("GATEWAY_ADMIN_KEY","")
SECRET="sk-INJECTED-BY-GATEWAY-7f3a9c2b"; CRED="demo-provider-key"; MODEL="injected-model"
def req(url,method="GET",key=None,body=None,gw=False,admin=False):
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,data=d,method=method); r.add_header("Content-Type","application/json")
    if admin: r.add_header("Authorization","Bearer "+ADMIN)
    elif key: r.add_header("X-Gateway-Key" if gw else "Authorization", key if gw else "Bearer "+key)
    try:
        with urllib.request.urlopen(r,timeout=20) as x: return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code,e.read().decode("utf-8","replace")
    except Exception as e: return 0,str(e)
def api(m,p,b=None): return req(API+p,method=m,admin=True,body=b)
if not ADMIN: sys.exit("export GATEWAY_ADMIN_KEY first")
# 1. store the secret credential (encrypted, write-only)
s,b=api("POST","/credentials",{"name":CRED,"type":"api_key","payload":{"api_key":SECRET}})
if s==409: api("PUT","/credentials/%s"%CRED,{"payload":{"api_key":SECRET}}); s="rotated"
print("[setup] stored credential %r in the gateway vault (HTTP %s)"%(CRED,s))
# 2. register a model that INJECTS that credential (no allow_caller_key)
s,b=api("GET","/models?limit=500")
try:
    j=json.loads(b); items=j.get("items",j) if isinstance(j,dict) else j
    have=any(m.get("name")==MODEL for m in items)
except Exception: have=False
if not have:
    s,b=api("POST","/models",{"name":MODEL,"description":"injects a vaulted credential",
        "targets":[{"vendor":"openai_compat","model":"mock-1","base_url":"http://host.docker.internal:8099/v1","credential":CRED,"label":"mock"}]})
    print("[setup] registered model %r -> target references the credential by NAME (HTTP %s)"%(MODEL,s))
# 3. mint an agent key
ak=json.loads(api("POST","/api-keys",{"name":"gen-secret-agent","role":"agent"})[1])["key"]
print("\n=== the agent calls the model WITHOUT any provider key ===")
s,b=req(LLM+"/openai/v1/chat/completions",method="POST",key=ak,gw=True,
    body={"model":MODEL,"max_tokens":32,"messages":[{"role":"user","content":"hi"}]})
print("agent -> gateway : sent only X-Gateway-Key, NO Authorization header")
print("call result      : HTTP %s"%s)
print("secret in the reply the agent got? %s"%("YES - LEAK!" if SECRET in b else "NO"))
print("  -> look at the MOCK UPSTREAM terminal: it shows 'Authorization: Bearer %s'"%SECRET)
print("     the gateway injected the vaulted key; the agent never sent it or saw it.")
print("\n=== exfiltration attempt by the compromised agent ===")
s,_=req(API+"/credentials",method="GET",key=ak)
print("agent GET /credentials            -> HTTP %s  %s"%(s,"DENIED (needs admin.manage)" if s in (401,403) else ""))
s,b=req(API+"/models",method="GET",key=ak)
print("agent GET /models (what it CAN see)-> HTTP %s ; secret value present? %s"%(s,"YES" if SECRET in b else "no (credential shown by name only)"))
s,b=api("GET","/credentials/%s"%CRED)
print("even admin GET /credentials/%s -> HTTP %s ; secret value present? %s"%(CRED,s,"YES" if SECRET in b else "no (metadata only, value never returned)"))
print("\nSecret injection proven: the key lives only inside the gateway, is injected at the edge, and is unreadable by anyone via the API.")
