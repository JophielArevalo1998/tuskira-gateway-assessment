# Live deployment design — automated gateway ↔ AiSOC loop

> **Status:** built and demonstrated — see [live-build.md](live-build.md) for the
> build and [attacks.md](attacks.md) for the five attacks run against it. A local
> Kubernetes (`kind`) cluster runs the gateway, with a bridge + AiSOC sandbox as a
> continuous, automated detect-and-respond loop — no batch files, no "would-call":
> telemetry streams live and containment is actually executed, under a policy gate.

This is the live system: the same controls a bench test would exercise, but wired
into a real cluster with a continuous pipeline, so it behaves the way a production
SOC integration would.

---

## 1. Goal and scope

| | An offline test | Live (this system) |
|---|---|---|
| Telemetry | export to a file, analyse after the fact | continuous **stream** (tail the pods' stdout) |
| Detection | run the analysis once, by hand | detectors running **continuously** on the stream |
| Response | a "would-call" in the ledger | **executed** against the control-plane API, under a **blast-radius gate** |
| Platform | one laptop, docker compose | a real **kind** cluster: namespaces, services, NetworkPolicies |

**In scope:** a working, local, automated loop good enough to demo and to learn
from. **Out of scope (for now):** cloud (EKS), Kafka streaming, autonomous
high-blast-radius response — all are on the roadmap (§8).

---

## 2. Architecture

```
            real + adversarial agents  (MCP :8080 / LLM :8082)
                          │
                          ▼
   ┌───────────────────────────────────────────┐
   │              THE GATEWAY (k8s)             │   data plane / sensor / actuator
   │   mcp │ api(:8081) │ llm   Deployments     │
   │   Postgres · ClickHouse · Redis            │
   └───────────────────────────────────────────┘
        ▲  control-plane API            │  analytics API (GET /analytics/*, ClickHouse)
        │  (revoke/tighten/disable)     ▼
   ┌───────────────────────────────────────────┐
   │                 THE BRIDGE                 │   the one new component
   │  streamer  — polls /analytics every N s    │
   │  responder — executes vetted actions       │
   │  policy    — blast-radius gate (auto/human) │
   └───────────────────────────────────────────┘
        │  normalized events            ▲  proposed action + verdict
        ▼                               │
   ┌───────────────────────────────────────────┐
   │        AiSOC (continuous detection)        │   reactive brain
   │   DETECT → TRIAGE → HUNT → RESPOND          │
   │   + incident web UI                         │
   └───────────────────────────────────────────┘
```

**Why this shape:** the gateway is deliberately *not* a detection engine — it
emits telemetry (ClickHouse-backed analytics API, OTel, stdout) and exposes a
control-plane API to act. Detection lives in AiSOC. The **bridge** is the glue
that makes them one live loop: it turns the gateway's pull-based telemetry into
a continuous feed for AiSOC, and turns AiSOC's decisions into executed gateway
actions — safely.

---

## 3. The loop, step by step

1. Agents call tools (MCP) and models (LLM) through the gateway. Every routed
   action becomes a record in ClickHouse.
2. **Bridge streamer** polls the gateway analytics API every few seconds —
   `GET /analytics/logs` (MCP) and `GET /analytics/llm-logs` (LLM), paginated
   by timestamp — normalizes each row into AiSOC's event shape, and feeds it to
   AiSOC (its ingest API / topic). State: the last-seen `(timestamp, request_id)`
   cursor, persisted so restarts don't double-feed.
3. **AiSOC** runs DETECT → TRIAGE → HUNT → RESPOND continuously. When it decides
   on containment it emits a **proposed action** (e.g. `revoke key <id>`,
   `tighten profile <id>`, `disable connector <id>`) with a confidence and a
   blast-radius tier.
4. **Bridge responder** receives the proposed action, runs it through the
   **policy gate** (§5), and — if allowed — calls the gateway control-plane API:
   `DELETE /api-keys/{id}`, `PATCH /api-keys/{id}` (limits), `PUT /profiles/{id}/tools`,
   or the connector-disable route.
5. The gateway executes; the offending agent is contained at its next request.
   The action itself is recorded (bridge audit log + the gateway's own state).

---

## 4. The bridge (the component to build)

A small service (Python or Go) with three concerns. Keep it stateless except
for the stream cursor.

### 4a. Streamer
- Poll `GET /api/v1/analytics/logs?from=<cursor>&...` and
  `/analytics/llm-logs?from=<cursor>` on a short interval (2–5 s).
- Normalize to a common event: `{plane, ts, request_id, principal, key_id,
  client_ip, tool_name|model, status_code, error_code, tokens, cost, session_id}`.
- Push to AiSOC's ingest. Persist the `(ts, request_id)` cursor (a file/ConfigMap
  or small DB) so a restart resumes, not replays.
- **Content inspection caveat:** the list routes carry **no bodies**. For
  payload-based detection (prompt injection), fetch the one record's body via
  `GET /analytics/logs/{request_id}` — an **admin-only** route. Minimize this:
  fetch a body only when a row is already suspicious, or run the OTel/stdout
  path with `include_bodies` for content and keep the analytics API for metadata.

### 4b. Responder
- Expose a single internal endpoint AiSOC calls: `POST /respond {action, target,
  reason, tier, confidence}`.
- Map actions → gateway API calls:
  | Action | Gateway call |
  |---|---|
  | `revoke_key` | `DELETE /api-keys/{id}` |
  | `tighten_limits` | `PATCH /api-keys/{id}` `{"limits":{...}}` |
  | `tighten_profile` | `PUT /profiles/{id}/tools` (reduced allow-list) |
  | `disable_connector` | connector update/delete route |
- Everything it does is written to its own **audit log** (who/what/when/why) —
  this also fills the gateway's own gap (API-key lifecycle isn't audited; see
  [findings G2](findings.md)).

### 4c. Policy gate (blast-radius)
Mirror AiSOC's L0–L4 model. Decide auto vs human by **how many principals the
action affects** and **reversibility**:

| Tier | Example | Default |
|---|---|---|
| Low — single identity, reversible | revoke one compromised key; tighten one key's limits | **auto-execute** |
| Medium — single identity, structural | tighten one agent's profile | auto if confidence ≥ threshold, else approval |
| High — many identities / hard to undo | disable a shared connector; add an egress rule | **human approval** (Slack/console) |

Approval can be a Slack interactive message or a console action; until approved,
the proposal is queued, not executed.

---

## 5. Security model for the automation

The automation holds power over the gateway, so least privilege is the point.

- **Two keys, two jobs.**
  - *Streamer* → a **`viewer`** key (`*.read`). It only reads telemetry; it can
    never change anything. (Body fetches for content inspection need admin — see
    §4a; prefer the OTel/stdout path for content so the streamer stays read-only.)
  - *Responder* → an **admin** key. The gateway's roles are fixed
    (`admin` / `agent` / `viewer` / `platform-admin`) — there is **no
    fine-grained "responder" role**, so the responder key is effectively admin.
    Treat it accordingly:
    - its own dedicated key, nothing else uses it;
    - a **NetworkPolicy** so only the bridge pod can reach the control-plane
      API (`:8081`);
    - stored as a k8s Secret (sealed-secrets / external-secrets), rotated;
    - every action it takes logged in the bridge audit log.
- **Gateway master key** (`GATEWAY_MASTER_KEY`) encrypts the credential store;
  generate a real one (`go run ./cmd/gateway secrets genkey`) and never reuse
  the compose dev default.
- **NetworkPolicies** (the base manifests already ship one): agents reach only
  the MCP/LLM planes; only the bridge reaches the API plane's control routes;
  only the gateway reaches Postgres/ClickHouse/Redis.

> **Finding to carry over:** auth rejections (`401`) are not in the analytics
> feed ([findings G1](findings.md)), so the bridge streamer won't see
> revoked-key reuse. To detect that, also ship the gateway pods' **stderr**
> (the `authentication failed` lines) into the pipeline — a Vector/Fluent Bit
> sidecar or DaemonSet — and feed those to AiSOC too.

---

## 6. Deployment on kind — runbook

**Prerequisites:** Docker, `kind`, `kubectl`, and a clone of the
[gateway repo](https://github.com/Tuskira/ai-agent-gateway) and
[AiSOC](https://github.com/beenuar/AiSOC).

```sh
# 1) cluster
kind create cluster --name ai-soc

# 2) gateway namespace + secrets (master key + DB password), out-of-band
kubectl create namespace ai-gateway
MASTER=$(docker run --rm ghcr.io/tuskira/ai-agent-gateway:latest secrets genkey)
kubectl -n ai-gateway create secret generic gateway-secrets \
  --from-literal=GATEWAY_MASTER_KEY="$MASTER" \
  --from-literal=GATEWAY_DATABASE_PASSWORD="$(openssl rand -hex 16)"

# 3) gateway: the base splits the 3 planes; add ClickHouse (analytics) + Redis.
#    overlays/kind = local cluster; overlays/kind-redis = kind + session store.
#    For the full local loop you want kind + analytics(ClickHouse) + redis;
#    build a small combined overlay (overlays/kind-full) that layers them, then:
kubectl apply -k deploy/k8s/overlays/kind-full      # (overlay to generate at build time)
kubectl -n ai-gateway rollout status deploy/gateway-api

# 4) AiSOC (its own namespace); bring up its stack (Postgres/Redis/Kafka/api/agents/web)
kubectl create namespace aisoc
#    ...apply AiSOC's manifests (or run its compose inside the cluster)

# 5) mint the two gateway keys (from a shell with the admin bootstrap key)
#    viewer (streamer) + admin (responder); store each as a k8s Secret in `aisoc`

# 6) the bridge: deploy streamer+responder+policy, wired to both keys,
#    the gateway API service, and AiSOC's ingest/respond endpoints
kubectl apply -k bridge/k8s                          # (to build)

# 7) NetworkPolicies: only the bridge → gateway :8081 control routes
kubectl apply -f bridge/k8s/networkpolicy-responder.yaml
```

(The combined `overlays/kind-full` and the whole `bridge/` are what we build in
the next step — this doc is the blueprint.)

---

## 7. Driving traffic and verifying the loop

- **Real traffic:** point actual MCP clients (Claude Code / Cursor / VS Code)
  and LLM calls through the gateway so the telemetry is genuine (set
  `X-Session-Id` on both planes to correlate — see the gateway's
  observability docs).
- **Adversarial traffic:** run the assessment's generators
  ([scripts/](../scripts/)) on a schedule (a k8s CronJob) so detection is
  continuously exercised: compromised agent, injection, LLM abuse, enumeration.
- **Verify the loop closes itself:** trip a low-blast-radius case (a compromised
  key) and watch — within seconds — AiSOC raise the incident, the bridge
  auto-revoke, and the key's next call return `401`. Trip a high-blast-radius
  case and watch it **queue for approval** instead.
- **Watch it:** gateway console (`:8081`) for the analyst view, AiSOC web UI for
  incidents, bridge audit log for every executed action.

---

## 8. Hardening / production path

What changes when this graduates from a local demo:

1. **Transport:** poll → **OTel → OTel Collector → Kafka → AiSOC**. AiSOC
   already speaks Kafka; this decouples the bridge streamer and scales.
2. **Platform:** kind → **EKS/GKE** via `deploy/k8s/overlays/eks` (internal ALB,
   RDS Postgres, managed ClickHouse, the migrate-then-rollout deploy script with
   DORA metrics).
3. **Scale:** the MCP plane scales out with the Redis session store
   (`components/redis`); HPAs/PDBs ship in `base`.
4. **Autonomy:** widen what auto-executes as confidence in the detections grows,
   but keep the high-blast-radius tier human-gated.
5. **The responder-role gap:** push the vendor for a fine-grained "responder"
   role (only `apikey.manage` + `profile.update` + `connector.update`) so the
   automation isn't full admin — until then, network isolation + rotation is the
   mitigation.
6. **Close the observability gaps** ([findings](findings.md)): ship the gateway
   stderr for `401`s, and add API-key-lifecycle auditing (the bridge audit log is
   a stopgap).

---

## 9. Open decisions

- **AiSOC footprint:** the full stack runs LLM agents (needs an LLM key / cost).
  For an affordable local build, run AiSOC against a cheap or local model, or a
  rules-first detector with LLM only for triage summaries.
- **Approval channel:** Slack interactive messages vs a console/web approval —
  pick one for the human-gated tier.
- **Cursor durability:** file vs ConfigMap vs a tiny DB for the streamer cursor
  (start with a file on a PVC).

---

*Next: build `overlays/kind-full`, the `bridge/` service (streamer + responder +
policy), its manifests and NetworkPolicies, and a CronJob that runs the
adversarial generators — per the decisions in §9.*
