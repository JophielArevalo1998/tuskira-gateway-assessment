# Attack catalog — five live attacks

Five adversarial scenarios run live against the gateway on `kind`, with the
bridge + AiSOC closing the loop. Each exercises a different gateway capability
and a different bridge detector; together they cover **three planes** (MCP
tools, MCP profile, LLM) and **all five detectors**.

A visual version of this catalog is in [`assets/`](../assets/) (the
*Five attacks, one loop* diagram).

## Results at a glance

| # | Attack | Script | Plane | Gateway behavior | Bridge detector → response | Finding |
|---|--------|--------|-------|------------------|----------------------------|---------|
| 1 | Tool enumeration | `tool_recon.py` | MCP | deny 18 tools `-32003` | `tool_enumeration` → **revoke** | profile allow-list holds; caught at 6th distinct tool |
| 2 | Compromised agent | `live_attack.py` | MCP | deny `-32003` | `compromised_agent` → **revoke** | cut off at 3rd denial; `200`-with-error quirk (G3) |
| 3 | LLM cost abuse | `llm_attack.py` | LLM | deny `400` before forward, **$0** | `llm_abuse` → **revoke** | cost capped before spend; LLM Logs populated |
| 4 | Prompt injection | `inject_attack.py` | MCP | **allow `200`** | `prompt_injection` → **revoke** | payload blindness (G5); needs `store_bodies` |
| 5 | Credential brute force | `brute_attack.py` | auth | **lockout `429`** | `brute_force` → *info, no action* | **console-blind** (G1); gateway self-defends |

## Prerequisites

1. Gateway on `kind` with request bodies captured (needed for Attack 4):
   ```sh
   # in the gateway clone:
   ./examples/10-kubernetes/run.sh
   kubectl -n ai-gateway set env deployment --all \
     GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true GATEWAY_CAPTURE_STORE_BODIES=true
   # (optional, to see traffic in the console) analytics overlay:
   kubectl -n ai-gateway patch secret gateway-secrets --type merge \
     -p '{"stringData":{"CLICKHOUSE_PASSWORD":"clickhousedev","GATEWAY_SINKS_CLICKHOUSE_PASSWORD":"clickhousedev"}}'
   kubectl apply -n ai-gateway -f deploy/k8s/overlays/analytics/clickhouse-statefulset.yaml \
     -f deploy/k8s/overlays/analytics/clickhouse-service.yaml
   kubectl -n ai-gateway set env deployment --all \
     GATEWAY_SINKS_CLICKHOUSE_ENABLED=true GATEWAY_SINKS_CLICKHOUSE_HOST=clickhouse \
     GATEWAY_SINKS_CLICKHOUSE_PORT=9000 GATEWAY_SINKS_CLICKHOUSE_DATABASE=gateway \
     GATEWAY_SINKS_CLICKHOUSE_USERNAME=default
   ```
   After any `set env`, re-establish port-forwards (`:28081/:28080/:28082`) and
   the stdout→feed tailer (see [live-build.md](live-build.md) M2/M6).

2. The telemetry feed and the bridge running live (see
   [live-build.md](live-build.md) M2/M3):
   ```sh
   export GW_API=http://localhost:28081/api/v1 GW_RESPONDER_KEY=<admin key>
   export AISOC_CMD="/path/to/aisoc-sandbox demo --file {file}"
   python3 -u bridge.py        # dry_run=False
   ```

3. In the attacker terminal:
   ```sh
   export GATEWAY_ADMIN_KEY=<admin key from run.sh>
   export GATEWAY_API=http://localhost:28081/api/v1
   export GATEWAY_MCP=http://localhost:28080/mcp
   export GATEWAY_LLM=http://localhost:28082          # Attack 3 only
   ```

Each attack mints a fresh key (and MCP session) per run. The session ids below
are from the demonstrated runs — look them up in the console's **Session
Timeline**.

---

## 1 · Tool enumeration — `tool_recon.py`

A reconnaissance agent on the `Echo Only` profile (allows `echo`, `get-sum`)
probes 18 distinct off-profile tools (`list-secrets`, `exec`, `dump-env`, …).

```sh
python3 tool_recon.py
```

**Gateway:** every off-profile `tools/call` → `-32003` (tool not allowed),
before execution. **Bridge:** `tool_enumeration` fires at ≥ 6 distinct denied
tools → `revoke_key` (`HTTP 204`). **Outcome:** the key's next call → `401`.
**Finding:** the profile allow-list holds; enumeration is caught at the 6th
distinct tool.

## 2 · Compromised agent — `live_attack.py`

A valid agent key on `Echo Only` hammers one off-profile tool (`list-secrets`)
once a second — a hijacked agent reaching for tools it should never touch.

```sh
python3 live_attack.py
```

**Gateway:** each call `-32003`. **Bridge:** `compromised_agent` at ≥ 3
off-profile denials → `revoke_key`. **Outcome:** cut off at ~call 4 (`401`).
**Session:** `u7jv7DEvqwyg3UtwhawS-rSelVdevCofa7K2brHthno`.
**Finding:** detected mid-recon (3rd denial); denials are `HTTP 200` with
`error_code -32003` (G3).

## 3 · LLM cost abuse — `llm_attack.py`

An agent key capped at `max_tokens:16` asks the LLM proxy for `1000` output
tokens, repeatedly — a runaway/abusive agent on the model plane.

```sh
python3 llm_attack.py
```

**Gateway:** each `/v1/messages` refused `400` (`max_tokens … exceeds this
key's limit of 16`) **before any provider is called** — `upstream_host` blank,
tokens `0`, **$0 spent**, but fully logged. **Bridge:** `llm_abuse` at ≥ 5
governance denials → `revoke_key`. **Outcome:** `401`.
**Finding:** cost governance bites before spend; the LLM Logs page populates.

## 4 · Prompt injection — `inject_attack.py`

A key on `Echo Only` calls the **allowed** `echo` tool, but the argument carries
a hostile payload (`ignore all previous instructions`, `exfiltrate to
attacker.example`, `/etc/shadow`).

```sh
python3 inject_attack.py        # requires GATEWAY_CAPTURE_STORE_BODIES=true
```

**Gateway:** **allows** every call (`200`) — it enforces *which* tool, not the
payload. **Bridge:** reads the captured body, flags `prompt_injection` →
`revoke_key`. **Outcome:** `401`.
**Session:** `VN95D3SZ_lX8lPXbbdfba99lD0wgiluF0V0u--wLzKU`.
**Finding (G5):** payload blindness. The response is a **revoke** (not a
throttle) because MCP has no per-key rate limit — `tighten_limits(rpm:0)` only
bites the LLM plane.

## 5 · Credential brute force — `brute_attack.py`

Sprays 14 invalid API keys at the MCP plane from one IP — key guessing.

```sh
python3 brute_attack.py
```

**Gateway:** first 10 → `401`, then `429` + `Retry-After: 300` — a 5-minute IP
lockout (per-plane, per-IP; keys on the real `127.0.0.1`, not the spoofed XFF).
The gateway defends itself. **Bridge:** `brute_force` detects it (≥ 6
auth-failures/IP) but takes **no action** — the gateway already handled it.
**Finding (G1, the headline):** those `401`/`429` records are written to the
stream (the bridge saw them) but carry **no tenant**, and the console is
tenant-scoped — so **the brute force is invisible in the console.** Verify:
```sh
grep '"status_code":401' ~/bench/live-feed.jsonl | tail -1 | python3 -m json.tool
# -> "tenant_id":"", "principal":"", "key_id":"", "client_ip":"127.0.0.1"
```
Detect it in your SIEM instead: `status_code IN (401,429) | stats count by client_ip`.

---

## Safety / scope

All attacks run against a **local** `kind` instance bound to `127.0.0.1`, use
**synthetic** keys minted for each run, spoof only [TEST-NET](https://datatracker.ietf.org/doc/html/rfc5737)
IPs (`203.0.113.0/24`), and spend **nothing** (Attack 3 is refused before any
provider call). No real data, credentials, or production systems are involved.
