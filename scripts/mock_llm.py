#!/usr/bin/env python3
# Free local OpenAI-compatible upstream: real token usage, $0, nothing leaves the host.
import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ANSWER = "Canned reply from the local mock upstream. No model was called; the gateway still metered this call."
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _s(self,c,o):
        b=json.dumps(o).encode(); self.send_response(c)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"): self._s(200,{"object":"list","data":[{"id":"mock-1","object":"model"}]})
        else: self._s(200,{"status":"ok"})
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0) or 0); raw=self.rfile.read(n) if n else b"{}"
        try: req=json.loads(raw)
        except Exception: req={}
        txt="".join(m.get("content","") if isinstance(m.get("content"),str) else json.dumps(m.get("content")) for m in req.get("messages",[]))
        pt=max(1,len(txt)//4)
        self._s(200,{"id":"chatcmpl-mock-%d"%int(time.time()*1000),"object":"chat.completion","created":int(time.time()),
            "model":req.get("model","mock-1"),"choices":[{"index":0,"message":{"role":"assistant","content":ANSWER},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":pt,"completion_tokens":220,"total_tokens":pt+220}})
ThreadingHTTPServer(("0.0.0.0",8099),H).serve_forever()
