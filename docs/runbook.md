# Runbook — full reproduction

Every scenario, end to end. All commands target `localhost`; all identities and
IPs are synthetic. Paths assume the scripts live in `./scripts/` and a working
directory `~/bench` for the telemetry feed.

> **Guardrails:** test only the local instance bound to `127.0.0.1`; no real or
> personal data through the gateway; the LLM scenarios use a free local mock
> upstream (zero spend); blur any real `gk_…` admin key in anything you share.

---

## 0. One-time setup

From a local clone of the [gateway repo](https://github.com/Tuskira/ai-agent-gateway):

```sh
# stack up with analytics (dashboard tiles) + bodies (so the feed carries payloads)
GATEWAY_SINKS_CLICKHOUSE_ENABLED=true GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true \
  docker compose -f deploy/docker-compose.yml --profile analytics up -d

# wait for health
until curl -sf http://localhost:8081/api/v1/health >/dev/null; do sleep 2; done

# reference MCP tool server behind the 'everything' connector
PORT=23014 npx -y @modelcontextprotocol/server-everything streamableHttp &
sleep 3

# admin key (persists across restarts; paste your real one)
export GATEWAY_ADMIN_KEY=gk_...

# register (or re-discover) the 'everything' connector
CID=$(curl -s http://localhost:8081/api/v1/connectors -H "Authorization: Bearer $GATEWAY_ADMIN_KEY" \
  | jq -r '.items[]|select(.slug=="everything")|.id')
if [ -z "$CID" ]; then
  CID=$(curl -s -X POST http://localhost:8081/api/v1/connectors -H "Authorization: Bearer $GATEWAY_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{"name":"everything","slug":"everything","endpoint":"http://host.docker.internal:23014/mcp"}' | jq -r .id)
fi
curl -s -X POST "http://localhost:8081/api/v1/connectors/$CID/discover" -H "Authorization: Bearer $GATEWAY_ADMIN_KEY" >/dev/null

# tail both planes' telemetry into one feed (the hunt/AiSOC adapters read this)
./scripts/ship.sh &
```

For **AiSOC**, clone and install [beenuar/AiSOC](https://github.com/beenuar/AiSOC)
and use its sandbox (`aisoc-sandbox demo --file <scenario.json>`).

---

## Example 1 — Compromised agent + credential brute force → AiSOC

```sh
python3 scripts/gw_traffic.py --baseline 12 --probes 10 --spike 60 --bruteforce 16
```

**Gateway (console :8081):** Overview (calls, success rate), Access Logs (the
`-32003` denials, the spike), Top Agents (the compromised key at the top),
Session Timeline (the denied `get-env` in red).

```sh
python3 scripts/adapt.py                          # gateway feed → scenario.json
aisoc-sandbox demo --file ~/bench/scenario.json    # DETECT→TRIAGE→HUNT→RESPOND
```

**Expect:** AiSOC correlates the events into one high-confidence incident and
proposes `gateway.apikey.revoke` on the offender — the same key the gateway
logged.

---

## Example 2 — Prompt injection through an allowed tool → AiSOC

```sh
python3 scripts/inject.py       # sends injection payloads via everything__echo (all 200)
```

**Gateway:** Access Logs → open a `gen-injection` echo row → the request body
shows the full injection payload. The gateway **passed** it (`200`) but captured
it.

```sh
python3 scripts/adapt_inject.py                        # content-based → scenario-injection.json
aisoc-sandbox demo --file ~/bench/scenario-injection.json
```

**Expect:** AiSOC reads the captured payloads, flags **AML.T0051 prompt
injection**, high confidence, and proposes revoke/tighten. (Requires
`GATEWAY_SINKS_STDOUT_INCLUDE_BODIES=true`, set in step 0.)

---

## Example 3 — SSRF / egress guard (gateway-only)

```sh
./scripts/ssrf.sh
```

**Expect:** six malicious connector endpoints (cloud metadata + decimal/hex
encodings + internal IPs), **all** `400 egress_blocked`. Nothing reaches the
network, so there is nothing for the SIEM to investigate — the point of this
scenario.

---

## Example 4 — LLM resource abuse ("LLM-jacking") → AiSOC

Start the free mock upstream (zero spend), then run the abuse:

```sh
python3 scripts/mock_llm.py &            # local OpenAI-compatible upstream on :8099
# confirm the gateway container can reach it:
docker compose -f deploy/docker-compose.yml exec gateway wget -qO- http://host.docker.internal:8099/v1/models; echo

python3 scripts/llm_gov.py               # registers mock-chat, mints keys, runs 3 abuses
```

**Gateway:** Overview (LLM Agent Calls / Total Tokens / Total Cost tiles),
LLM Logs filtered to `gen-llm-abuser` (the `200`s next to the `max_tokens` /
`rpm` / `budget` denial rows).

```sh
python3 scripts/adapt_llm.py                      # → scenario-llm.json
aisoc-sandbox demo --file ~/bench/scenario-llm.json
```

**Expect:** ~20 allowed, ~21 denials; AiSOC flags **AML.T0034 cost harvesting**
and proposes revoke + zero the rate limit.

---

## Example 5 — Tool enumeration → the hunt

```sh
python3 scripts/tool_recon.py            # one agent probes 18 distinct off-profile tools (all -32003)
```

**Gateway:** Access Logs filtered to `error_code = -32003` (one principal, many
tool names), or the Session Timeline (one session, 18 tools, ~95% errors).

```sh
python3 scripts/hunt_recon.py            # proactive hunt over the feed
```

**Expect:** the hunt flags the enumerating principal (≥6 distinct denied tools →
ENUMERATION) and correctly does **not** flag a single-tool off-profile slip.
`scripts/hunt.py` runs both the enumeration and the LLM-abuse hypotheses.

---

## Loop closed — execute the containment and prove it

```sh
python3 scripts/revoke_demo.py
```

**Expect:** `[1]` the key works (`initialize` + `echo` → `200`) → `[2]` revoke
executed (`DELETE /api-keys/{id}` → `204`) → `[3]` the key's next `initialize`
→ `401`, cut off.

The `401` is recorded in the **gateway application log**, not Access Logs:

```sh
docker compose -f deploy/docker-compose.yml logs --since 5m gateway | grep -i "authentication failed"
```

---

## Example 6 — Secret injection / credential vaulting

Use the header-reflecting mock (frees :8099 first):

```sh
pkill -f mock_llm.py 2>/dev/null
python3 scripts/mock_secret.py &         # logs the Authorization header it receives
python3 scripts/secret_demo.py           # stores a credential, injects it, tries to exfil
```

**Expect:**
- the **mock terminal** prints `Authorization received from gateway: Bearer
  sk-INJECTED-BY-GATEWAY-…` (the gateway injected the vaulted key);
- the **demo** shows the agent sent no key, got no secret back, `GET
  /credentials` → `403`, and the value is never returned even to admin.

---

## Cleanup

```sh
# stop the mocks
pkill -f mock_llm.py; pkill -f mock_secret.py
# remove the synthetic test keys (optional)
for n in gen-compromised gen-injection gen-llm-agent gen-llm-abuser gen-recon gen-secret-agent; do
  curl -s -H "Authorization: Bearer $GATEWAY_ADMIN_KEY" "http://localhost:8081/api/v1/api-keys?limit=500" \
    | jq -r --arg n "$n" '.items[]|select(.name|startswith($n))|.id' \
    | while read id; do curl -s -X DELETE "http://localhost:8081/api/v1/api-keys/$id" -H "Authorization: Bearer $GATEWAY_ADMIN_KEY"; done
done
# tear down the stack (add -v to also drop its data volumes)
docker compose -f deploy/docker-compose.yml down
```
