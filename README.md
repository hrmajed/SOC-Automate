# SOC Automate

A local, context-aware alert triage console for SOC analysts. When an alert arrives, an AI investigation agent:

- **pivots across EDR, CloudTrail and identity-provider (Okta) logs** with read-only tool calls;
- **retrieves environment context** from your network map, past incident reports and compliance obligations (local RAG) to explain *why this alert matters here*;
- **reconstructs the attack story** as a cited timeline, attack path and MITRE ATT&CK mapping, with human-approved response recommendations;
- **keeps telemetry private.** Personal data is pseudonymised before any model call, and models run locally through Ollama. A deterministic mock backend means the whole app works with no model and no network.
- **defends itself against adversarial AI attacks:** prompt injection in log fields, RAG poisoning and tampering, tool misuse, and output exfiltration. It ships an adversarial eval harness that measures those defences.

The goal is to cut mean time to respond (MTTR) by doing the first hour of context gathering before a human opens the ticket. The agent never takes actions itself.

## Quick start

Requirements: Python 3.11+, Node 20+.

```bash
# backend
python3 -m venv .venv            # or: uv venv .venv
.venv/bin/pip install -e "backend[dev]"

# frontend
(cd frontend && npm install)

# run both (API on :8765, console on :4317)
./scripts/dev.sh
```

Open http://127.0.0.1:4317, pick an alert, and click **Investigate with AI**.

To run the pieces separately:

```bash
cd backend && ../.venv/bin/uvicorn soc_copilot.api:app --port 8765
cd frontend && npm run dev          # proxies /api to 127.0.0.1:8765 (override with SOC_API_URL)
```

### Using a local model (optional)

If [Ollama](https://ollama.com) is running, the backend detects it at startup and uses it for tool calling and narrative writing. Otherwise it falls back to the deterministic mock planner.

```bash
ollama pull llama3.1:8b          # or qwen2.5:14b, mistral-nemo: any model with tool calling
SOC_LLM_BACKEND=auto SOC_OLLAMA_MODEL=llama3.1:8b ./scripts/dev.sh
# optional semantic embeddings instead of the offline hashing embedder:
ollama pull nomic-embed-text && SOC_EMBEDDINGS=ollama ./scripts/dev.sh
```

| Variable | Default | Meaning |
|---|---|---|
| `SOC_LLM_BACKEND` | `auto` | `auto` (Ollama if reachable, else mock), `ollama`, or `mock` |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama endpoint |
| `SOC_OLLAMA_MODEL` | `llama3.1:8b` | Chat model; falls back to the first installed chat model |
| `SOC_EMBEDDINGS` | `hashing` | `hashing` (offline TF-IDF) or `ollama` |
| `SOC_MAX_TOOL_CALLS` | `30` | Tool-call budget per investigation |

## Demo scenario

The synthetic data (`backend/soc_copilot/data/`) models a fictional biotech, Helix Dynamics, and one realistic intrusion:

1. A Finance analyst opens `Invoice_Q3_Overdue.docm`. Word spawns encoded PowerShell, which pulls a loader from a known C2.
2. The attacker persists through a scheduled task. **The task description contains a prompt injection aimed at AI triage tools.**
3. The attacker dumps LSASS, then RDPs to the admin jump host with a privileged account, which violates segmentation policy.
4. The attacker reads plaintext AWS keys, which a past incident said should have been removed, and exfiltrates them.
5. MFA fatigue lets the attacker in through Okta from a Tor exit, where they enroll a new MFA device.
6. The attacker assumes a data role, downloads about 3 GB of clinical-trial PHI (GDPR and HIPAA in scope), tries to stop CloudTrail, and creates a backdoor access key.

Five alerts sit in the queue. Four of them are fragments of this intrusion, and investigating any one reconstructs the whole path. The fifth (**ALR-1004**, encoded PowerShell on the CI server) is a known false positive, and the agent explains why by citing past incident INC-2025-0147. A poisoned wiki page in the knowledge base tries to whitelist the C2 IP. It is quarantined at ingest.

## Architecture

```
frontend/  Next.js + TypeScript + Tailwind + shadcn/ui triage console
backend/soc_copilot/
  store.py       vendor log parsers → common evidence schema (EDR, CloudTrail, Okta)
  pii.py         reversible, identity-aware pseudonymisation (users, emails, SSNs, cards, phones, AWS keys, secrets)
  rag.py         chunking, offline hashing embedder or Ollama embeddings, numpy vector store,
                 trust tiers, ingest quarantine, SHA-256 integrity manifest
  tools.py       read-only tools: lookup_asset/identity/ip, query_edr/cloudtrail/idp, search_knowledge, get_related_alerts
  llm.py         pluggable backends: Ollama (native tool calling), deterministic mock, adversarial stand-ins
  guardrails.py  injection scanner (patterns, base64, Unicode tags, delimiters), spotlighting,
                 tool policy (allow-list, schemas, caps, budget, loop guard), output guard
  attack.py      deterministic ATT&CK and ATLAS mapping of evidence
  agent.py       guarded tool-calling loop plus grounded synthesis (timeline, path, verdict, context, actions)
  evals/         adversarial harness: every attack runs with guardrails OFF vs ON
  api.py         FastAPI (REST plus NDJSON streaming of the agent trace)
```

**Design principle: grounding before generation.** The model chooses the pivots and may write the prose. The timeline, ATT&CK mapping, attack path and severity floor come from normalised evidence through deterministic rules. A fooled or hallucinating model cannot invent events, downgrade a strongly malicious verdict, cite evidence that does not exist, or smuggle URLs into the report.

## Tests and evals

```bash
cd backend
../.venv/bin/pytest -q                      # unit + integration tests (includes the adversarial suite)
../.venv/bin/python -m soc_copilot.evals    # attack-success table, guardrails OFF vs ON
cd ../frontend && npm run lint && npm run typecheck
```

Current eval result: **attack success 100% with guardrails off, 0% with guardrails on** across 10 cases, and 0 false positives over about 400 benign log fields and knowledge chunks. The same suite runs in the console under **Guardrail evals**.

## Limitations

- All data is synthetic. Connectors for real SIEM, EDR, cloud and IdP sources are the next step.
- The default embedder is lexical (feature-hashed TF-IDF) so it runs anywhere. Switch to `nomic-embed-text` for semantic retrieval.
- ATT&CK rules are scenario-sized, not a complete detection library.
- The injection scanner uses patterns and heuristics. It is one layer of several, and the output guard and tool policy are designed to hold even when it is bypassed.
