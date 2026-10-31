# Close the loop: execute the containment AiSOC/hunt recommended, and prove it.
# Mint an offender key -> show it works -> revoke it via the gateway API -> show it's dead.
import json,os,time,urllib.request,urllib.error
API=os.environ.get("GATEWAY_API","http://localhost:8081/api/v1"); MCP="http://localhost:8080/mcp"
ADMIN=os.environ["GATEWAY_ADMIN_KEY"]; IP="203.0.113.88"
def api(m,p,b=None):
    d=json.dumps(b).encode() if b is not None else None
    r=urllib.request.Request(API+p,data=d,method=m); r.add_header("Content-Type","application/json"); r.add_header("Authorization","Bearer "+ADMIN)
    try:
        with urllib.request.urlopen(r,timeout=15) as x: return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code,e.read().decode("utf-8","replace")
    except Exception as e: return 0,str(e)
def mcp(key,body,sid=None):
    r=urllib.request.Request(MCP,data=json.dumps(body).encode(),method="POST")
    for k,v in [("Content-Type","application/json"),("Accept","application/json, text/event-stream"),("Authorization","Bearer "+key),("X-Forwarded-For",IP)]: r.add_header(k,v)
    if sid: r.add_header("Mcp-Session-Id",sid)
    try:
        with urllib.request.urlopen(r,timeout=15) as x: return x.status,x.headers.get("Mcp-Session-Id"),x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code,None,e.read().decode("utf-8","replace")
    except Exception as e: return 0,None,str(e)
def init(key): return mcp(key,{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"revoke-demo","version":"0.1"}}})
print("=== closing the loop: execute the revoke, then prove it ===")
s,b=api("POST","/api-keys",{"name":"gen-compromised-live","role":"agent"})
j=json.loads(b); key=j["key"]; kid=j["id"]
print("offender key minted   id = %s"%kid)
st,sid,_=init(key)
print("\n[1] BEFORE revoke  initialize      -> HTTP %s  %s"%(st,"the key works" if st==200 else ""))
if st==200:
    cst,_,cb=mcp(key,{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"everything__echo","arguments":{"message":"pre-revoke call"}}},sid)
    print("    BEFORE revoke  echo (tool call) -> HTTP %s  %s"%(cst,"allowed" if cst==200 and '\"error\"' not in cb else "denied"))
rst,_=api("DELETE","/api-keys/%s"%kid)
print("\n[2] RESPONSE EXECUTED  revoke via gateway API  (DELETE /api-keys/%s) -> HTTP %s"%(kid,rst))
time.sleep(1)
st2,_,_=init(key)
print("\n[3] AFTER revoke   initialize      -> HTTP %s  %s"%(st2,"DENIED - key revoked, agent cut off" if st2 in (401,403) else "(unexpected: %s)"%st2))
print("\nLoop closed: recommended -> executed on the gateway -> the agent's next request is refused.")
