#!/usr/bin/env bash
# Trajectix DFIR Agent — SANS Find Evil! Demo Runner
set -e

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TRAJECTIX DFIR AGENT — SANS Find Evil! Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Prerequisite checks ──────────────────────────────────────────────

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "ERROR: ANTHROPIC_API_KEY is not set."
    echo ""
    echo "  Option 1: export ANTHROPIC_API_KEY=sk-ant-..."
    echo "  Option 2: add ANTHROPIC_API_KEY to .env in this directory"
    echo ""
    exit 1
fi

if [ -n "$LOOPPAUSE_API_KEY" ]; then
    echo "Mode: FULL LOOPPAUSE MODE"
    echo "  Human approval routed to soc-lead@example.com"
    echo "  Ed25519 signature verification enabled"
else
    echo "Mode: PIPELOCK MODE (terminal gate)"
    echo "  At the isolation gate, press:"
    echo "    [R] — Deny (triggers self-correction demo)"
    echo "    [A] — Approve (second gate, after re-investigation)"
    echo "    [I] — Inspect AFR chain"
    echo ""
    echo "  (Set LOOPPAUSE_API_KEY in .env for full LoopPause flow)"
fi

echo ""

# ── Install dependencies ─────────────────────────────────────────────

echo "Installing dependencies..."
pip install -r requirements.txt -q
echo "Dependencies ready."
echo ""

# ── Clear previous session ───────────────────────────────────────────

if [ -f "trajectix_session.jsonl" ]; then
    echo "Clearing previous session: trajectix_session.jsonl"
    rm -f trajectix_session.jsonl
fi

# ── Run the agent ────────────────────────────────────────────────────

echo "Starting investigation..."
echo ""
python src/agent.py fixtures/

# ── Post-run chain verification ──────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  POST-RUN AFR CHAIN VERIFICATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python - <<'PYEOF'
import sys
sys.path.insert(0, '.')
from src.afr_logger import AFRLogger

afr   = AFRLogger('trajectix_session.jsonl')
valid = afr.verify_chain()
chain = afr.get_chain()

print(f"  Total entries: {len(chain)}")
print()
print("  Last 3 AFR entries:")
for entry in chain[-3:]:
    import json
    print(json.dumps({
        "step_id":    entry["step_id"],
        "event_type": entry["event_type"],
        "content":    entry["content"][:80] + ("..." if len(entry["content"]) > 80 else ""),
        "chain_hash": entry["chain_hash"][:16] + "...",
    }, indent=4))
    print()
PYEOF

echo ""
echo "AFR log: trajectix_session.jsonl"
echo ""
