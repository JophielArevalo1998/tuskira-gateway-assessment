# Live build — step by step (local kind)

Build the automated gateway ↔ AiSOC loop on a local `kind` cluster, milestone by
milestone. Design rationale is in [live-deployment.md](live-deployment.md); this
is the hands-on build.

**Shape:** gateway on kind (all 3 planes) → the **bridge** tails its telemetry,
detects live, runs the **AiSOC sandbox** for an investigation ledger, and
executes containment on the gateway's control API under a policy gate.

**Fits ~5–6 GB** (gateway + kind + the bridge + the sandbox on demand). On a
32 GB laptop: close heavy apps, and if WSL is stingy with RAM, raise its limit
in `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
memory=24GB
processors=12
```
(then `wsl --shutdown` and reopen).

---

## M0 — Prerequisites (WSL/Ubuntu)

```sh
# Docker Desktop with the WSL2 backend is already installed (the bench used it).
# kind + kubectl:
[ -x /usr/local/bin/kind ] || { curl -Lo /tmp/kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64 && sudo install /tmp/kind /usr/local/bin/kind; }
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo install kubectl /usr/local/bin/
kind version && kubectl version --client
```

You already have `aisoc-sandbox` from the bench (the bridge calls it). Verify:
`aisoc-sandbox --help`.

---

## M1 — Gateway on kind (the vendor's one-command deploy)

From your gateway clone:

```sh
cd ~/ai-agent-gateway
./examples/10-kubernetes/run.sh        # builds the image (~3-4 min), creates kind
                                        # cluster 'ai-gateway-example', rolls out
                                        # 3 planes + an in-cluster 'everything' server,
                                        # bootstraps an admin key, runs a tool call.
```

It leaves the three planes **port-forwarded**:
`api :28081`, `mcp :28080`, `llm :28082`, and prints the **admin key**. Keep it.

Turn on request bodies (so the bridge can detect injection), then restart:

```sh
kubectl -n ai-gateway set env deployment --all GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true
kubectl -n ai-gateway rollout restart deploy && kubectl -n ai-gateway rollout status deploy/gateway-mcp
```

Console: <http://localhost:28081>. (ClickHouse/analytics isn't needed — the
bridge reads telemetry from the pods' stdout; add the analytics overlay later if
you want the Overview dashboards.)

---

## M2 — Start the telemetry feed

```sh
mkdir -p ~/bench
( kubectl logs -f -n ai-gateway deploy/gateway-mcp --all-containers 2>/dev/null &
  kubectl logs -f -n ai-gateway deploy/gateway-api --all-containers 2>/dev/null &
  kubectl logs -f -n ai-gateway deploy/gateway-llm --all-containers 2>/dev/null & ) \
  | grep --line-buffered '"record":' >> ~/bench/live-feed.jsonl &
```

(If you scale `gateway-llm` past 1 replica, add `-l <its label>
--max-log-requests 10` so you catch every pod; `kubectl get pods -n ai-gateway
--show-labels` shows the label.)

---

## M3 — The bridge (the live loop)

```sh
cd ~/bench            # put bridge.py here (from the repo's bridge/)
# a dedicated responder key (admin — it executes containment):
export GW_ADMIN=<the admin key run.sh printed>
RESP=$(curl -s -X POST http://localhost:28081/api/v1/api-keys \
  -H "Authorization: Bearer $GW_ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"bridge-responder","role":"admin"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")

export GW_API=http://localhost:28081/api/v1
export GW_RESPONDER_KEY="$RESP"
export AISOC_CMD="aisoc-sandbox demo --file {file}"

# first run in DRY_RUN to watch it detect + propose without executing:
DRY_RUN=1 python3 bridge.py
# once you trust it, run for real (drop DRY_RUN):
python3 bridge.py
```

Watch `~/bench/bridge-state/audit.log` and `.../incidents/` fill up.

---

## M4 — Adversarial traffic (exercise the loop)

Run the five attacks at the **kind ports** (note `28080/28081/28082`). Full
per-attack walkthrough in [attacks.md](attacks.md):

```sh
cd ~/bench
export GATEWAY_ADMIN_KEY="$GW_ADMIN"
export GATEWAY_API=http://localhost:28081/api/v1
export GATEWAY_MCP=http://localhost:28080/mcp
export GATEWAY_LLM=http://localhost:28082
python3 tool_recon.py       # 1 enumeration  -> bridge: revoke
python3 live_attack.py      # 2 compromised  -> bridge: revoke
python3 llm_attack.py       # 3 LLM cost     -> bridge: revoke  ($0 spent)
python3 inject_attack.py    # 4 injection    -> bridge: revoke  (needs store_bodies)
python3 brute_attack.py     # 5 brute force  -> gateway lockout (bridge: info)
```

To keep it running continuously, wrap these in a loop or a k8s CronJob.

---

## M5 — Verify the loop closes itself

Trip a low-blast-radius case (enumeration or a compromised agent) and watch, in
seconds:

1. `tool_recon.py` fires the probes → the gateway denies each (`-32003`);
2. the bridge logs an **INCIDENT**, writes an **AiSOC investigation ledger**
   (`bridge-state/incidents/*.ledger.txt`), and **auto-revokes** the key;
3. that key's next call comes back `401` — the agent is cut off.

A high-blast-radius case (one you've mapped to a non-`low` tier, e.g. disabling a
shared connector) lands in `bridge-state/pending/` for approval instead.

**Three views:** the gateway console (`:28081`), the bridge `audit.log`, and the
per-incident ledgers.

---

## Notes

- **Transport:** the local build tails pod stdout (simple, gives bodies). For a
  ClickHouse deployment, switch the bridge to poll `/analytics/*` and give the
  streamer a read-only `viewer` key (see [live-deployment.md](live-deployment.md)).
- **Least privilege:** only the responder key is admin; lock it down and rotate.
- **Policy gate:** `AUTO_TIERS=low` auto-executes single-identity reversible
  actions; widen it only as you trust the detections, and keep high-blast-radius
  actions human-gated.
- **Cleanup:** `kind delete cluster --name ai-gateway-example`.
```
