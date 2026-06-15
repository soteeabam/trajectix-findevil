# Trajectix DFIR Agent — SANS Find Evil! Submission

**Autonomous incident response with human-in-the-loop oversight and tamper-evident forensic logging**

Trajectix is an AI-powered DFIR agent that investigates lateral movement incidents using
Claude Opus, detects unsafe agent behaviours in real time (ALE taxonomy), and gates every
irreversible action through a cryptographically-signed human authorisation checkpoint
(LoopPause) before execution. A Pipelock terminal fallback keeps the demo fully runnable
without a live LoopPause account.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TRAJECTIX DFIR AGENT                         │
│                                                                     │
│  ┌─────────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │ Protocol SIFT   │    │  Claude Opus      │    │  AFR Logger   │  │
│  │ Adapter         │───▶│  Reasoning Loop   │───▶│  SHA-256      │  │
│  │                 │    │  (claude-opus-4-6)│    │  Hash Chain   │  │
│  │ • event logs    │    │                   │    │  OCSF v1.3    │  │
│  │ • network conns │    │  Multi-turn conv  │    │  JSONL output │  │
│  │ • process tree  │    │  + ALE detection  │    │               │  │
│  │ • PS artifacts  │    │                   │    └───────────────┘  │
│  └─────────────────┘    └────────┬──────────┘                       │
│                                  │ RECOMMEND ISOLATION               │
│                                  ▼                                   │
│                         ┌────────────────┐                           │
│                         │  ALE-T005 Gate │                           │
│                         └───────┬────────┘                           │
│                         ┌───────┴────────────────────┐               │
│                         │  LoopPause API             │               │
│                         │  POST /v1/pauses           │               │
│                         │  Ed25519 signature verify  │               │
│                         │  authorization_type check  │               │
│                         └──────────┬─────────────────┘               │
│                                    │ DENIED + comment                 │
│                                    ▼                                  │
│                         ┌──────────────────┐                          │
│                         │ SELF_CORRECTION  │                          │
│                         │ Inject comment → │                          │
│                         │ re-investigate   │                          │
│                         └──────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘

  Fallback (no LOOPPAUSE_API_KEY): Pipelock terminal [A]/[R]/[I] gate
  Proxy (ANTHROPIC_BASE_URL set):  All Claude calls route through Trajectix proxy
```

---

## Scenario: Lateral Movement — The Red Herring

The investigation is seeded with a deliberate forensic trap:

**Red herring:** `HOST-WORKSTATION-04` shows 3 failed login attempts (Event 4625) from
external IP `185.220.101.47` (known Tor exit node) — visually the most alarming indicator.

**Actual source:** `HOST-DC-01` has 6 × Event 4648 (logon with explicit credentials)
targeting `HOST-SERVER-02` over SMB 445 — the true lateral movement vector.

**Attack chain:**
```
185.220.101.47 → HOST-DC-01 (svc_backup compromised)
                     │
                     │ Event 4648 × 6  (explicit credentials)
                     │ SMB 445
                     ▼
              HOST-SERVER-02
                     │
                     │ cmd.exe → powershell.exe (encoded)
                     │ Cobalt Strike beacon → 185.220.101.47:4444
                     │ Mimikatz LSASS dump
                     ▼
              185.220.101.47 (C2)
```

### Investigation narrative

1. **Turn 1:** Agent focuses on Event 4625 failures on WS-04, concludes it is the source,
   outputs `RECOMMEND ISOLATION: HOST-WORKSTATION-04`
2. **ALE-T005 fires** — irreversible action without confirmation gate
3. **LoopPause / Pipelock gate activates** — human reviewer catches the error
4. **DENIED** with comment: *"wrong host — check DC logs, event 4648 shows credential use
   from HOST-DC-01 not WS-04"*
5. **SELF_CORRECTION logged** — comment injected as new user message
6. **Turn 2:** Agent re-examines Event 4648, correlates with SMB connections and process
   artifacts, outputs `RECOMMEND ISOLATION: HOST-DC-01`
7. **LoopPause / Pipelock gate** — reviewer approves
8. **IRREVERSIBLE_ACTION_APPROVED** — `network_isolation(HOST-DC-01)` simulated

Every step is logged to `trajectix_session.jsonl` with a SHA-256 hash chain.

---

## ALE Detections Demonstrated

| Technique | Name | Fired When |
|-----------|------|------------|
| ALE-T001 | Logic Guessing | Agent uses assumption language near an action keyword |
| ALE-T005 | Silent Reasoning Loop / Irreversible Action | Isolation recommended without prior confirmation gate |

Full taxonomy: [doi.org/10.5281/zenodo.19964382](https://doi.org/10.5281/zenodo.19964382)

---

## Project Structure

```
sans-findevil/
├── src/
│   ├── agent.py                 # Main investigation loop + LoopPause + Pipelock
│   ├── ale_detector.py          # Keyword pattern matching, ALE-T001–T005
│   ├── afr_logger.py            # SHA-256 hash chain JSONL logger (OCSF v1.3)
│   └── protocol_sift_adapter.py # Fixture shim / Protocol SIFT MCP bridge
├── fixtures/
│   ├── windows_event_logs.json  # 50 events: red herring (WS-04) + real source (DC-01)
│   ├── network_connections.json # SMB lateral movement + C2 beacon records
│   ├── powershell_artifacts.json# Cobalt Strike beacon + Mimikatz on SERVER-02
│   └── process_artifacts.json   # svchost→cmd→powershell chain on SERVER-02
├── README.md
├── run_demo.sh
├── requirements.txt
└── .env.example
```

---

## Quick Start

### 1. Install dependencies

```bash
cd sans-findevil
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
# Optionally add LOOPPAUSE_API_KEY for full LoopPause mode
```

### 3. Run the demo

```bash
bash run_demo.sh
```

Or run manually:

```bash
python src/agent.py fixtures/
```

### 4. Pipelock controls (when no LOOPPAUSE_API_KEY)

When the agent recommends host isolation, Pipelock pauses execution:

- **[A]** Approve — action proceeds
- **[R]** Rollback — deny and inject SOC lead correction (triggers self-correction)
- **[I]** Inspect — print full AFR chain to terminal

Press **[R]** on the first gate to see the full self-correction sequence.

---

## LoopPause Mode (full production flow)

Set `LOOPPAUSE_API_KEY` in `.env` to use the LoopPause human-in-the-loop API:

1. Agent POSTs to `POST /v1/pauses` with action details
2. LoopPause routes an approval request to `soc-lead@example.com`
3. Agent polls `GET /v1/pauses/{id}` until decision arrives
4. Response is Ed25519 signature-verified against the LoopPause well-known key
5. `authorization_type: system_fallback` → treated as DENIED (not a human decision)
6. Comment from the reviewer triggers SELF_CORRECTION and re-investigation

---

## Trajectix Proxy Integration

To route Claude calls through the Trajectix proxy (for production AFR interception):

```bash
ANTHROPIC_BASE_URL=http://localhost:8080 python src/agent.py fixtures/
```

All `anthropic.Anthropic` calls use `base_url` from this env var.

---

## AFR Log Format

Each entry in `trajectix_session.jsonl`:

```json
{
  "step_id": 3,
  "timestamp": "2026-04-25T14:20:01.123456+00:00",
  "event_type": "ALE_DETECTION",
  "content": "1 ALE technique(s) in turn 1",
  "content_hash":  "<sha256 of content>",
  "previous_hash": "<sha256 of prior entry content>",
  "chain_hash":    "<sha256(previous_hash + content_hash + timestamp)>",
  "metadata": { "techniques": [...] },
  "class_uid":    4001,
  "category_uid": 4,
  "severity_id":  4,
  "status": "In Progress",
  "activity_id": 1
}
```

Verify chain integrity after a session:

```bash
python -c "
import sys; sys.path.insert(0,'.')
from src.afr_logger import AFRLogger
AFRLogger('trajectix_session.jsonl').verify_chain()
"
```

---

## LoopPause

LoopPause is Trajectix's hosted HITL (Human-In-The-Loop) API — a purpose-built
authorisation checkpoint for autonomous AI agents. Rather than embedding ad-hoc
approval emails in each agent, teams `POST /v1/pauses` with a structured action
description, then poll until a human decision arrives — signed with Ed25519 so
the agent can cryptographically prove the decision came from a real human
(`authorization_type: human`) rather than an automated fallback.

LoopPause is available at: [looppause.com](https://looppause.com)
