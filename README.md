# Tuskira AI Agent Gateway — Live Detect-and-Respond Assessment

An independent, hands-on security assessment of the open-source
**[Tuskira AI Agent Gateway](https://github.com/Tuskira/ai-agent-gateway)**, run
from a SOC analyst's perspective. It stands up a **live** instance of the gateway
on a local Kubernetes (`kind`) cluster, builds a continuous
**detect → investigate → respond** loop around it (a bridge + the AiSOC sandbox),
and runs **five live attacks** that each exercise a different gateway control —
verifying what fires, executing containment through the gateway's own API, and
documenting the strengths and observability gaps that only surface under live
testing.

![Five attacks, one loop](assets/five-attacks.png)

> **Scope.** Everything runs against a **local** `kind` instance bound to
> `127.0.0.1`, uses **synthetic** keys minted per run, spoofs only
> [TEST-NET](https://datatracker.ietf.org/doc/html/rfc5737) IPs
> (`203.0.113.0/24`), and spends **nothing** on LLM calls (Attack 3 is refused
> before any provider is contacted). No real data, credentials, or production
> systems are involved. This is a functional security assessment of a tool's
> controls, not an exploit dump. See [Responsible disclosure](#responsible-disclosure).

---

## Why test an AI-agent gateway at all?

AI agents are a new attack surface, and unusual in ways that matter to a SOC:

- **They act with real credentials and real tools.** An agent reads files, calls
  APIs and tools (via MCP), and talks to LLMs — all with delegated authority. A
  hijacked agent identity is a stolen set of hands.
- **Classic SOC tooling is blind to them.** A SIEM/EDR/WAF has no native concept
  of *"which agent is doing what, with which tool, on whose behalf."*
- **An AI-agent gateway is the chokepoint that fixes this.** It sits in front of
  every agent action — tool calls (MCP) and model calls (LLM) — so it can both
  **see** every action and **stop** it in real time, and serve as the **hands**
  that carry out containment.

This assessment tests whether the gateway actually delivers that: does it
enforce, does it record, and can detection be turned into real, autonomous
containment?

---

## The live system

```
   attacker (agent)
        │  MCP tools/call · /v1/messages
        ▼
  ┌───────────────┐   deny / allow / lockout      ┌──────────────┐
  │  AI Agent     │ ───────────────────────────▶  │ MCP connector│
  │  Gateway      │                               │  / LLM plane │
  │  (on kind)    │ ── telemetry (stdout) ──┐      └──────────────┘
  └───────▲───────┘                         │
          │ DELETE /api-keys (revoke)        ▼
          │                           ┌─────────────┐   scenario   ┌────────┐
          └───────────────────────────│   Bridge    │ ───────────▶ │ AiSOC  │
            contain (control-plane API)│ (detectors) │ ◀─────────── │(sandbox)│
                                       └─────────────┘  recommend   └────────┘
```

- **Gateway** — the tool under test, on a real `kind` cluster (three planes:
  MCP `:28080`, API `:28081`, LLM `:28082`). It enforces policy and emits a
  telemetry record for every request.
- **Bridge** — a ~350-line Python loop **we built** (not part of either tool). It
  tails the gateway's stdout, runs detectors over a rolling window, calls AiSOC
  for an investigation, and executes containment through the gateway's API under
  a blast-radius policy gate. In production this role is a SOAR platform.
- **AiSOC** — the open-source [`beenuar/AiSOC`](https://github.com/beenuar/AiSOC)
  sandbox, as the investigation engine (DETECT → TRIAGE → HUNT → RESPOND).

Build it: **[docs/live-build.md](docs/live-build.md)** · design:
**[docs/live-deployment.md](docs/live-deployment.md)**.

---

## The five attacks

Each attack hits a different plane and a different detector; together they cover
all three planes and all five detectors. **Full mechanical walkthrough:**
**[docs/attacks.md](docs/attacks.md)**.

| # | Attack | Script | Plane | Gateway behavior | Bridge → response | Finding |
|---|--------|--------|-------|------------------|-------------------|---------|
| 1 | Tool enumeration | `tool_recon.py` | MCP | deny 18 tools `-32003` | `tool_enumeration` → **revoke** | caught at 6th distinct tool |
| 2 | Compromised agent | `live_attack.py` | MCP | deny `-32003` | `compromised_agent` → **revoke** | cut off at 3rd denial; `200`+error (G3) |
| 3 | LLM cost abuse | `llm_attack.py` | LLM | deny `400`, **$0 spent** | `llm_abuse` → **revoke** | cost capped before spend |
| 4 | Prompt injection | `inject_attack.py` | MCP | **allow `200`** | `prompt_injection` → **revoke** | payload blindness (G5) |
| 5 | Credential brute force | `brute_attack.py` | auth | **lockout `429`** | `brute_force` → *info* | console-blind (G1) |

Attacks 1–4 end in an **autonomous** revoke (the attacker's next call → `401`);
Attack 5 is handled by the gateway's own lockout.

More diagrams in [`assets/`](assets/): the architecture loop
([detect-respond-loop](assets/detect-respond-loop.png)), a step-by-step
walkthrough ([containment-walkthrough](assets/containment-walkthrough.png)), and
a one-glance version ([containment-at-a-glance](assets/containment-at-a-glance.png)).

---

## Key findings

The gateway is a strong control point: it closes the agent-visibility blind spot,
enforces authorization and LLM cost/rate limits *on the live path*, and exposes a
control-plane API that turns detection into **real, autonomous containment**. The
gaps a SOC should know:

- **The console cannot show authentication abuse (the headline).** Auth failures
  and lockouts *are* recorded, but with **no tenant/key id**, and every console
  view is **tenant-scoped** — so brute force and revoked-key reuse are invisible
  in the UI (Attack 5). Treat the gateway as a **telemetry source** and ship its
  stdout to your SIEM.
- **API-key lifecycle isn't audited.** A revoke changes a field; the *action*
  leaves no event.
- **Denials are `HTTP 200` with `error_code`.** Alert on `error_code`, not HTTP
  status.
- **Payload blindness + no per-key MCP rate limit.** An injection rides through
  an allowed tool (`200`); the right MCP containment is a revoke, not a throttle.
- **The lockout's `X-Forwarded-For` trust is config-critical** (default is safe —
  confirmed live).

Full detail with evidence: **[docs/findings.md](docs/findings.md)**.

---

## Reproduce it

1. **Build the live system** — [docs/live-build.md](docs/live-build.md): gateway
   on `kind`, bodies captured, the stdout→feed tailer, and the bridge live.
2. **Run the attacks** — [docs/attacks.md](docs/attacks.md): each script, its
   command, and what to watch, in a second terminal.

The short version (after the build):

```sh
# terminal 1 — the bridge (live)
python3 -u bridge.py

# terminal 2 — an attack
export GATEWAY_ADMIN_KEY=<admin key>  GATEWAY_API=http://localhost:28081/api/v1
export GATEWAY_MCP=http://localhost:28080/mcp  GATEWAY_LLM=http://localhost:28082
python3 tool_recon.py     # or live_attack / llm_attack / inject_attack / brute_attack
```

---

## Repository layout

```
tuskira-gateway-assessment/
├── README.md                 this file
├── docs/
│   ├── attacks.md            the five attacks — mechanical walkthrough + reproduce
│   ├── findings.md           strengths + gaps, with live evidence
│   ├── live-build.md         build the live kind + bridge + AiSOC loop (M0–M6)
│   └── live-deployment.md    the live-system design (architecture, bridge)
├── assets/                   the four diagrams (.png for GitHub, .html sources)
├── bridge/
│   ├── bridge.py             the live detect-and-respond loop (~350 LOC, stdlib)
│   └── README.md             the bridge's detectors, responses, and how to run it
└── scripts/
    ├── tool_recon.py         Attack 1  tool enumeration
    ├── live_attack.py        Attack 2  compromised agent (persistent)
    ├── llm_attack.py         Attack 3  LLM cost abuse (max_tokens, $0 spent)
    ├── inject_attack.py      Attack 4  prompt injection through an allowed tool
    └── brute_attack.py       Attack 5  credential brute force → lockout
```

All scripts are pure Python standard library, take `GATEWAY_ADMIN_KEY` and the
`GATEWAY_API/MCP/LLM` endpoints from the environment, and target `localhost`
only (the `kind` ports `:28081/:28080/:28082`).

---

## Responsible disclosure

The gaps here were observed on a **local** instance of an open-source tool —
design/observability observations, not weaponised exploits. The observability
findings (especially G1) should be shared with the vendor
(`security@tuskira.ai`) before this repository is made public; it is intended to
stay **private** until then. Nothing in this repo contains real credentials:
every key is read from the environment or minted synthetically per run, and all
IPs are documentation/test ranges.

---

## References

- Tuskira AI Agent Gateway — <https://github.com/Tuskira/ai-agent-gateway>
- beenuar / AiSOC (investigation sandbox) — <https://github.com/beenuar/AiSOC>
- MITRE ATT&CK — <https://attack.mitre.org> · MITRE ATLAS — <https://atlas.mitre.org>
