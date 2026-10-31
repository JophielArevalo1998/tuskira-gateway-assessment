#!/usr/bin/env bash
# Tail the gateway's stdout telemetry into a single feed the hunt/AiSOC
# adapters read. Captures BOTH planes: {"type":"access",...} (MCP) and
# {"type":"llm_call",...} (LLM). Run from the gateway repo root.
#
#   ./ship.sh        # appends to ~/bench/gateway-events.jsonl
mkdir -p ~/bench
docker compose -f deploy/docker-compose.yml logs -f --no-log-prefix gateway \
  | grep --line-buffered '"record":' >> ~/bench/gateway-events.jsonl
