# Findings

A SOC-analyst assessment of the Tuskira AI Agent Gateway, produced by running
**five live attacks** against a local `kind` deployment with a bridge + AiSOC
closing a real detect → investigate → respond loop (see
[attacks.md](attacks.md) and [live-deployment.md](live-deployment.md)). Every
point cites what was observed on that live system.

> Several of these findings — most importantly **G1** — came out of
> **cross-checking three surfaces against each other**: the gateway's control
> plane, the raw telemetry stream (what the bridge reads), and the admin
> console. Where they disagreed is where the real findings were.

---

## Strengths

### S1 — It closes the agent-visibility blind spot (for routed traffic)
Every authenticated agent action that reaches a tool or model is recorded and
attributed to an identity and source IP, on the console and in the stdout feed.
A SIEM/EDR/WAF has no native view of this. *(Caveat: this holds for routed,
authenticated traffic; auth-failure traffic is a different story — see **G1**.)*
*Evidence:* Access Logs and LLM Logs show every `tools/call` / `/v1/messages`
with `principal`, `key_id`, `client_ip`, `tool_name`/`model`, `status_code`,
`error_code`.

### S2 — Authorization is enforced per agent, on the call
An agent scoped to a profile cannot use a tool outside it: the gateway denies
with JSON-RPC `-32003` after routing but before execution. The distinction is
authentication (a valid key) vs authorization (may this key call *this* tool).
*Evidence:* **Attack 1** — 18 distinct off-profile tools, all `-32003`.
**Attack 2** — repeated off-profile `list-secrets`, all `-32003`.

### S3 — LLM usage is metered and capped by identity, before spend
The gateway governs the LLM plane per key: an oversized generation
(`max_tokens` → `400`), request rate (`rpm` → `429`), and dollar budget
(`daily_usd` → `429`) are refused **before any upstream call**, and every call —
allowed or refused — is captured. No SIEM/EDR can provide this.
*Evidence:* **Attack 3** — a key capped at `max_tokens:16` asked for `1000`;
every call refused `400` with `upstream_host` blank and token counts `0`
(**$0 spent**), fully logged in LLM Logs.

### S4 — Credential headers are masked before capture
Even with body/header capture on, the gateway masks credential headers before
they are written to the log — `Authorization: "****"` in the access record.
*Evidence:* confirmed live in the Attack-5 feed records.

### S5 — Detection converts into containment — live and autonomous
The gateway's telemetry is portable (stdout → any SIEM), and its control-plane
API executes the decision: `DELETE /api-keys/{id}` revokes a key and every
replica evicts it within milliseconds (`pg_notify`). Here this ran **as a live
loop with no human in the path** for low-blast-radius actions.
*Evidence:* **Attacks 1–4** — the bridge detected, ran an AiSOC investigation,
and executed `revoke_key` (`HTTP 204`); the attacker's next call came back
`401`, cut off in seconds.

---

## Gaps and limitations

### G1 — The console cannot show authentication abuse  *(headline)*
Auth failures (invalid or revoked keys) and the IP lockout **are recorded** to
the telemetry stream — the MCP access log deliberately wraps auth so a burst of
`401`s is captured. **But** those records carry **no `tenant_id` and no
`key_id`** (auth failed before a principal), and **every console analytics view
is tenant-scoped** (`WHERE tenant_id = ?`). So they are silently dropped from
Access Logs, Overview, and Session Timeline — every console view. The only
in-product signal is `/health`'s `locked_ips` counter: a bare number, no
IP/time/detail, **API-plane only** (it doesn't reflect MCP/LLM-plane lockouts).
*Evidence:* **Attack 5** — 10 `401`s then 4 `429`s from one IP; the bridge
(reading raw stdout) detected `brute_force`, but the console showed **nothing**.
A feed record confirms why: `"tenant_id":""`, `"principal":""`, `"key_id":""`,
`"status_code":401`, `"client_ip":"127.0.0.1"`.
*Impact:* **high for a SOC relying on the console.** Credential brute force and
revoked-key reuse — the things a security team most wants to see — are invisible
in the gateway's own UI.
*Recommendation:* treat the gateway as a **telemetry source, not a security
console** — ship its stdout to your SIEM, where
`status_code IN (401,429) | stats count by client_ip` catches it (exactly what
the bridge does). For the vendor: add an IP-level / tenant-less auth-failure
view and surface lockouts across all planes.

### G2 — API-key lifecycle isn't audited
A revoke is a soft-delete (`UPDATE api_keys SET revoked_at = now()`); the key
then shows `Revoked` in the API Keys list, but **the revoke action leaves no
event** — who revoked it, when, and why exist only outside the gateway. The
`auth_audit` trail covers console *user* events (logins, user management), not
API-key mint/revoke.
*Evidence:* verified in `internal/store/postgres/apikey.go` (no audit write in
`Revoke`); the only record of the live revokes is the bridge's `audit.log`.
*Impact:* medium — weak accountability for the credentials that front the agents;
your SOAR layer must own the response audit trail.

### G3 — Denials are `HTTP 200` with an `error_code`
A profile denial is delivered as `HTTP 200` carrying JSON-RPC `-32003`, not a
`4xx`. Alerting on HTTP status misses every authorization denial; you must alert
on `error_code`.
*Evidence:* **Attacks 1, 2** — denied `tools/call` rows show `status 200`,
`error_code -32003`.
*Impact:* low (by design) but a real detection-engineering footgun.

### G4 — The IP lockout's `X-Forwarded-For` trust is config-critical
The lockout scopes to the caller's real IP, walking `X-Forwarded-For` only to the
first untrusted hop (`api.trusted_proxies`). The **default is safe** — untrusted
XFF is ignored. But set `trusted_proxies` too broadly and an attacker can spoof
`X-Forwarded-For` to dodge the lockout or lock out innocents.
*Evidence:* **Attacks 2–5** sent `X-Forwarded-For: 203.0.113.150`; every record
shows `client_ip: 127.0.0.1` — the spoofed header was captured but **not
trusted**.
*Impact:* medium — correct `trusted_proxies` config is security-critical.

### G5 — Payload blindness, and MCP has no per-key rate limit
The gateway enforces *which tool* runs, not *what the payload contains* — so a
hostile instruction inside an allowed tool's arguments passes through with `200`.
And per-key `rpm`/budget limits are enforced **only on the LLM plane**; the MCP
plane's only limiter is the auth-failure lockout. So a throttle cannot contain an
MCP-borne attacker — a revoke is required.
*Evidence:* **Attack 4** — three injection payloads all returned `200`; the
bridge caught them from the **captured body** (needs `capture.store_bodies`) and
the right containment was a **revoke**, not `tighten_limits(rpm:0)`.
*Impact:* medium — content inspection is the operator's/SOAR's job; design
response actions for the plane the attack is on.

---

## What was proven vs. what wasn't
- **Proven, live, autonomous:** real-time detection from the gateway's stream,
  an AiSOC investigation per incident, and containment through the gateway's API
  with no human in the path for low-blast-radius actions.
- **A policy choice, stated plainly:** AiSOC's own `RespondAgent` defaults to L1
  ("recommendations only, human executes"). The loop ran autonomously because the
  **bridge's** `AUTO_TIERS=low` gate chose to auto-execute single-identity,
  reversible actions. Higher-blast-radius actions queue for approval.
- **The bridge is custom glue, not a product feature.** The gateway and the AiSOC
  sandbox are off-the-shelf; the ~350-line bridge (`bridge/bridge.py`) ties them
  into a loop. In production that role is a SOAR platform.
- **Scope.** A single-node `kind` cluster on a laptop; the AiSOC sandbox is its
  deterministic offline mode, not the full streaming platform. One operational
  limit surfaced: during a pod rollout the bridge's `kubectl logs` feed drops, so
  it is briefly blind — a ClickHouse-polling transport would not be.

---

## Rating

| Dimension | Rating | Note |
|---|---|---|
| Agent visibility (routed traffic) | ★★★★★ | The blind spot it closes is the whole point, and it does it well. |
| Enforcement (authz / rate / cost) | ★★★★★ | Real-time, on the live path; LLM cost capped before spend. |
| Containment / actuator | ★★★★★ | Real, fast, and demonstrated autonomous via the control-plane API. |
| Security observability **in the console** | ★★☆☆☆ | Rich for routed traffic; **blind to auth abuse** and key lifecycle (G1, G2). |
| Detection-engineering ergonomics | ★★★☆☆ | `200`-with-error-code, XFF trust, and payload blindness need care (G3, G4, G5). |

**Overall:** a strong, genuinely useful control point for AI-agent
infrastructure — the right architecture for a problem traditional tooling can't
see, with real-time enforcement and a clean containment API. Its main limitation
is that it is a **telemetry-and-enforcement plane, not a security console**: feed
its stream to your SIEM and own the response there (as the bridge demonstrates),
and don't rely on its UI to show you credential abuse.
