# The bridge — live detect-and-respond

A continuous loop between the gateway and AiSOC. It tails the gateway's
telemetry, detects incidents over a rolling window, runs the **AiSOC sandbox**
to produce an investigation ledger per incident, and **executes containment**
against the gateway's control-plane API under a blast-radius policy gate.

This is the always-on version of the bench's `ship.sh → adapt.py →
aisoc-sandbox --file`.

## How it runs (local kind)

```
  gateway pods ──kubectl logs ──▶ ~/bench/live-feed.jsonl ──▶ bridge.py
                                                                 │
                        AiSOC sandbox (ledger) ◀────────────────┤
                        gateway control API (revoke/tighten) ◀──┘
```

1. **Tail the gateway telemetry into the feed** (the live `ship.sh`):
   ```sh
   mkdir -p ~/bench
   ( kubectl logs -f -n ai-gateway deploy/gateway-mcp --all-containers 2>/dev/null &
     kubectl logs -f -n ai-gateway deploy/gateway-api --all-containers 2>/dev/null &
     kubectl logs -f -n ai-gateway deploy/gateway-llm --all-containers 2>/dev/null & ) \
     | grep --line-buffered '"record":' >> ~/bench/live-feed.jsonl
   ```
   (Enable bodies so injection detection works:
   `kubectl -n ai-gateway set env deployment --all GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true`
   then `kubectl -n ai-gateway rollout restart deploy`.)

2. **Mint a responder key** (admin — it executes containment) and run the bridge:
   ```sh
   export GW_API=http://localhost:28081/api/v1      # kind port-forward
   export GW_RESPONDER_KEY=gk_...                     # dedicated admin key
   export AISOC_CMD="aisoc-sandbox demo --file {file}"  # or "" to skip ledgers
   python3 bridge.py
   ```

Start in **`DRY_RUN=1`** to watch it detect and *propose* without executing;
drop it once you trust the detections.

## Config (env)

| Var | Default | Meaning |
|---|---|---|
| `GW_API` | `http://localhost:28081/api/v1` | gateway control-plane API |
| `GW_RESPONDER_KEY` | — | admin key the responder uses (required unless `DRY_RUN`) |
| `FEED` | `~/bench/live-feed.jsonl` | the telemetry feed to tail |
| `STATE_DIR` | `~/bench/bridge-state` | `incidents/`, `pending/`, `audit.log` |
| `AISOC_CMD` | `aisoc-sandbox demo --file {file}` | how to run the sandbox (`{file}` = scenario); `""` skips |
| `AUTO_TIERS` | `low` | tiers that auto-execute; others are queued in `pending/` |
| `WINDOW_SEC` / `COOLDOWN_SEC` | 300 / 600 | detection window / per-incident cooldown |
| `ENUM_THRESHOLD` | 6 | distinct denied tools = enumeration |
| `DRY_RUN` | 0 | 1 = detect + propose, never execute |

## Detections and responses

| Incident | Signal | Action | Tier |
|---|---|---|---|
| `tool_enumeration` | one principal, ≥`ENUM_THRESHOLD` distinct denied tools | revoke key | low (auto) |
| `compromised_agent` | one principal, ≥3 off-profile denials | revoke key | low (auto) |
| `llm_abuse` | one key, ≥5 LLM governance denials | revoke key | low (auto) |
| `prompt_injection` | allowed tool call carrying a hostile payload | revoke key | low (auto) |
| `brute_force` | one IP, ≥6 auth failures / lockouts | none — gateway already locks out | info (review) |

Every incident writes a ledger + scenario to `STATE_DIR/incidents/`, every
action to `STATE_DIR/audit.log`, and anything above the auto tier to
`STATE_DIR/pending/` for human approval.

## Security

- The bridge holds the **responder key** (admin — the gateway has no
  fine-grained responder role). Give it its own key, restrict reachability to
  the gateway API, rotate it, and keep the audit log.
- On kind the telemetry comes from `kubectl logs` (authorized by your
  kubeconfig), so the bridge needs **no gateway read key** — only the responder
  key. (The analytics-API-poll transport, for a ClickHouse deployment, would
  add a read-only `viewer` key for the streamer.)
