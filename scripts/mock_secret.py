# Mock LLM upstream that LOGS the Authorization header it receives (to prove
# the gateway injected a vaulted credential), but never echoes it to the caller.
import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ANSWER = "Generic reply. The upstream received an injected credential (see the log line); it is NOT returned to the caller."
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
        auth=self.headers.get("Authorization","(none)")
        print("[mock upstream] %s  Authorization received from gateway: %s"%(self.path,auth),flush=True)
        n=int(self.headers.get("Content-Length",0) or 0); _=self.rfile.read(n) if n else b"{}"
        self._s(200,{"id":"chatcmpl-mock","object":"chat.completion","created":int(time.time()),"model":"mock-1",
            "choices":[{"index":0,"message":{"role":"assistant","content":ANSWER},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":5,"completion_tokens":20,"total_tokens":25}})
ThreadingHTTPServer(("0.0.0.0",8099),H).serve_forever()
