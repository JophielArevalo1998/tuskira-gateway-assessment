import json,os,sys,time,urllib.request,urllib.error
API=os.environ.get("GATEWAY_API","http://localhost:8081/api/v1"); MCP=os.environ.get("GATEWAY_MCP","http://localhost:8080/mcp")
ADMIN=os.environ["GATEWAY_ADMIN_KEY"]; IP="203.0.113.150"
TOOLS=["list-secrets","read-file","write-file","exec","run-command","dump-env","printEnv","get-credentials","ssh-keys","list-users","port-scan","http-fetch","delete-file","list-connectors","rotate-key","sampleLLM","getTinyImage","add"]
def api(m,p,b=None):
    d=json.dumps(b).encode() if b is not None else None
    r=urllib.request.Request(API+p,data=d,method=m); r.add_header("Content-Type","application/json"); r.add_header("Authorization","Bearer "+ADMIN)
    try:
        with urllib.request.urlopen(r,timeout=15) as x: return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code,e.read().decode("utf-8","replace")
    except Exception as e: return 0,str(e)
def cid():
    _,b=api("GET","/connectors?limit=500")
    for it in json.loads(b).get("items",[]):
        if it.get("slug")=="everything": return it["id"]
    sys.exit("no 'everything' connector - register it (quickstart) and keep the npx server up")
def profile(name,c,tools):
    _,b=api("GET","/profiles?limit=500"); pid=None
    for it in json.loads(b).get("items",[]):
        if it.get("name")==name: pid=it["id"]; break
    if pid is None: _,b=api("POST","/profiles",{"name":name}); pid=json.loads(b)["id"]
    api("PUT","/profiles/%s/tools"%pid,{"tools":[{"connector_id":c,"tool_name":t} for t in tools]}); return pid
def mint(name):
    _,b=api("POST","/api-keys",{"name":name,"role":"agent"}); return json.loads(b)["key"]
def mcp(key,body,sid=None):
    r=urllib.request.Request(MCP,data=json.dumps(body).encode(),method="POST")
    for k,v in [("Content-Type","application/json"),("Accept","application/json, text/event-stream"),("Authorization","Bearer "+key),("X-Forwarded-For",IP)]: r.add_header(k,v)
    if sid: r.add_header("Mcp-Session-Id",sid)
    if body.get("method")=="tools/call": r.add_header("X-Agent-Profile-Name","Echo Only")
    try:
        with urllib.request.urlopen(r,timeout=15) as x: return x.status,x.headers.get("Mcp-Session-Id"),x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code,None,e.read().decode("utf-8","replace")
    except Exception as e: return 0,None,str(e)
c=cid(); profile("Echo Only",c,["echo","get-sum"]); key=mint("gen-recon-%d"%int(time.time()))
_,sid,_=mcp(key,{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"recon","version":"0.1"}}})
den=0
for t in TOOLS:
    _,_,b=mcp(key,{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"everything__"+t,"arguments":{}}},sid)
    if "-32003" in b: den+=1
    time.sleep(0.2)
print("probed %d distinct tools, %d denied -32003, offender gen-recon from %s"%(len(TOOLS),den,IP))
print("Console: Access Logs -> filter error_code -32003. Then: python3 hunt_recon.py")
