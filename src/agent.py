#!/usr/bin/env python3
"""
Trajectix DFIR Agent — SANS Find Evil! Hackathon Submission

Autonomous forensic investigation agent with:
  - AFR (Agentic Flight Recorder) SHA-256 hash chain logging
  - Real-time ALE (Autonomous Logic Escalation) detection
  - LoopPause Ed25519-signed human authorization gate
  - Pipelock terminal fallback with self-correction demo
  - Protocol SIFT adapter for fixture/live data

Usage:
    python src/agent.py fixtures/
    ANTHROPIC_BASE_URL=http://localhost:8080 python src/agent.py fixtures/
"""

import base64
import json
import os
import platform
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

import anthropic
import requests
from colorama import Fore, Style, init as colorama_init
from dotenv import load_dotenv

# Allow running from project root with: python src/agent.py
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.afr_logger import AFRLogger
from src.ale_detector import ALEDetector
from src.protocol_sift_adapter import (
    get_event_logs,
    get_network_connections,
    get_powershell_artifacts,
    get_process_artifacts,
    set_fixtures_dir,
)

load_dotenv()
colorama_init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

ANTHROPIC_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY")
LOOPPAUSE_API_KEY  = os.getenv("LOOPPAUSE_API_KEY")
LOOPPAUSE_BASE_URL = "https://api.looppause.com"
MODEL              = "claude-sonnet-4-6"
AFR_OUTPUT         = "trajectix_session.jsonl"
MAX_TURNS          = 8

W  = Fore.WHITE  + Style.BRIGHT
RD = Fore.RED    + Style.BRIGHT
Y  = Fore.YELLOW
C  = Fore.CYAN
G  = Fore.GREEN  + Style.BRIGHT
RS = Style.RESET_ALL

# ── System Prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a senior DFIR (Digital Forensics and Incident Response) analyst "
    "investigating a suspected lateral movement incident on a corporate Windows network.\n\n"
    "Your investigation methodology:\n"
    "1. Start with authentication failures (Event ID 4625) — they indicate external "
    "brute-force and initial access attempts and are the most immediately visible red flags\n"
    "2. Review successful logons (4624) to map authentication flows\n"
    "3. Examine explicit credential logons (Event ID 4648) — this event records WHERE "
    "credentials are being used FROM, which identifies the lateral movement source host\n"
    "4. Correlate with network connections to confirm SMB lateral movement paths\n"
    "5. Identify process execution anomalies (4688) and PowerShell artifacts\n\n"
    "Key Event IDs:\n"
    "  4625 = Failed logon (external attack surface / brute force)\n"
    "  4624 = Successful logon (map authentication flows)\n"
    "  4648 = Logon with explicit credentials (CRITICAL — source of lateral movement)\n"
    "  4688 = Process creation (execution chain)\n\n"
    "When you have sufficient evidence, conclude with exactly:\n"
    "RECOMMEND ISOLATION: [hostname]\n"
    "EVIDENCE: [one-line primary indicator]\n\n"
    "Be concise and evidence-based."
)

# ── Terminal helpers ───────────────────────────────────────────────────────────

def _getch() -> str:
    """Read a single keypress without requiring Enter."""
    if platform.system() == "Windows":
        import msvcrt
        return msvcrt.getch().decode(errors="replace")
    import tty
    import termios
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _clear() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")


def _render_pipelock(hostname: str, evidence: str, context_snippet: str, afr: AFRLogger) -> None:
    """Draw the Pipelock terminal pause screen."""
    _clear()
    print()
    print(W + "━" * 55 + RS)
    print(RD + "  ⚠  TRAJECTIX PIPELOCK — EXECUTION PAUSED"           + RS)
    print(W + "━" * 55 + RS)
    print()
    print(Y  + "  ALE-T005 DETECTED: Irreversible Action Proposed"     + RS)
    print(     f"  Action:  Network isolation of {W}{hostname}{RS}")
    print(     f"  Evidence: {evidence[:70]}")
    print()
    print(     "  Agent reasoning (last 300 chars):")
    for line in context_snippet[:300].replace("\n", " ").split(". ")[:3]:
        if line.strip():
            print(f"    {line.strip()}.")
    print()
    chain_len = len(afr.get_chain())
    print(     f"  AFR chain: {chain_len} entries logged | Step {afr.step_id}")
    print()
    print(W + "─" * 55 + RS)
    print(C  + "  [A] APPROVE     — proceed with host isolation"        + RS)
    print(C  + "  [R] ROLLBACK    — block action, inject correction"    + RS)
    print(C  + "  [I] INSPECT     — print full AFR chain to terminal"   + RS)
    print(W + "─" * 55 + RS)
    print(W  + "  Awaiting human decision..."                           + RS)
    print()


def activate_pipelock(
    hostname: str,
    evidence: str,
    context_snippet: str,
    afr: AFRLogger,
) -> tuple[str, str]:
    """
    Display the Pipelock pause interface and wait for a single keypress.

    [A] → APPROVED, no comment
    [R] → DENIED with hardcoded SOC lead comment (enables self-correction demo
           without requiring a real LoopPause API key)
    [I] → Print full AFR chain, re-render

    Returns (decision, comment).
    """
    while True:
        _render_pipelock(hostname, evidence, context_snippet, afr)
        key = _getch().upper()

        if key == "I":
            _clear()
            print(C + "\n── AFR CHAIN ─────────────────────────────────────────" + RS)
            for entry in afr.get_chain():
                print(json.dumps(entry, indent=2))
                print()
            print(C + "── END OF CHAIN — press any key to return ────────────" + RS)
            _getch()
            continue  # re-render the gate

        elif key == "A":
            afr.log(
                "PIPELOCK_DECISION",
                f"Operator approved isolation of {hostname}",
                {"decision": "APPROVED", "operator_input": "A", "hostname": hostname},
            )
            print(G + f"\n  ✓ APPROVED — proceeding with isolation of {hostname}" + RS)
            time.sleep(0.8)
            return "APPROVED", ""

        elif key == "R":
            # Inject the SOC lead correction comment so the self-correction
            # sequence runs identically to full LoopPause mode.
            comment = (
                "wrong host — check the DC logs, event 4648 shows "
                "credential use from HOST-DC-01 not WS-04"
            )
            afr.log(
                "PIPELOCK_DECISION",
                f"Operator denied isolation of {hostname}",
                {
                    "decision":         "DENIED",
                    "operator_input":   "R",
                    "hostname":         hostname,
                    "injected_comment": comment,
                },
            )
            print(RD + f"\n  ✗ ROLLBACK — injecting SOC lead correction context" + RS)
            time.sleep(0.8)
            return "DENIED", comment

# ── LoopPause integration ─────────────────────────────────────────────────────

def _verify_looppause_signature(response: dict) -> None:
    """
    Verify the Ed25519 signature on a LoopPause response.
    Fetches the public key from the well-known endpoint.
    Raises on a real InvalidSignature; logs warning on network errors (demo mode).
    """
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    signature_b64     = response.get("signature")
    canonical_payload = response.get("canonical_payload")

    if not signature_b64 or not canonical_payload:
        print(f"{Y}[WARN] Response missing signature fields — skipping verification (demo mode){RS}")
        return

    try:
        with urllib.request.urlopen(
            f"{LOOPPAUSE_BASE_URL}/.well-known/looppause-signing-key.json",
            timeout=5,
        ) as r:
            key_data = json.loads(r.read())

        public_key = load_der_public_key(base64.b64decode(key_data["public_key"]))
        public_key.verify(
            base64.b64decode(signature_b64),
            canonical_payload.encode("utf-8"),
        )
        print(f"{G}[✓] Ed25519 signature VERIFIED{RS}")

    except urllib.error.URLError as exc:
        print(f"{Y}[WARN] Cannot reach LoopPause signing endpoint: {exc} — skipping (demo){RS}")
    except Exception as exc:
        if "InvalidSignature" in type(exc).__name__:
            print(f"{RD}[!] SIGNATURE VERIFICATION FAILED — payload may be tampered{RS}")
            raise
        print(f"{Y}[WARN] Signature verification error: {exc} — skipping (demo){RS}")


def call_looppause(hostname: str, evidence: str, afr: AFRLogger) -> tuple[str | None, str | None]:
    """
    POST a pause to LoopPause and poll for a decision.
    Returns (decision, comment) or (None, None) if unavailable → fall back to Pipelock.
    """
    headers = {
        "Authorization": f"Bearer {LOOPPAUSE_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "agent_id": "trajectix-dfir-agent",
        "action": {
            "type":        "network_isolation",
            "description": f"Isolate {hostname} — confirmed lateral movement source",
            "details":     {"hostname": hostname, "evidence": evidence},
        },
        "recipients": [{"channel": "email", "target": "looppausehq@gmail.com"}],
        "webhook_url":   "https://example.com/webhook",
        "timeout_hours": 1,
    }

    try:
        resp = requests.post(
            f"{LOOPPAUSE_BASE_URL}/v1/pauses",
            headers=headers,
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"{Y}[WARN] LoopPause unavailable: {exc} — falling back to Pipelock{RS}")
        return None, None

    pause_data = resp.json()
    pause_id   = pause_data.get("pause_id")
    if not pause_id:
        print(f"{Y}[WARN] LoopPause response missing pause_id — falling back to Pipelock{RS}")
        return None, None

    afr.log("LOOPPAUSE_PAUSE", f"Pause created: {pause_id}", {
        "pause_id": pause_id,
        "hostname": hostname,
        "evidence": evidence,
    })
    print(f"{C}[LoopPause] Pause {pause_id} created — routing to soc-lead@example.com{RS}")
    print(f"{C}[LoopPause] Polling for decision (60 s timeout)...{RS}")

    for attempt in range(20):
        time.sleep(3)
        try:
            poll = requests.get(
                f"{LOOPPAUSE_BASE_URL}/v1/pauses/{pause_id}",
                headers=headers,
                timeout=10,
            )
            if not poll.ok:
                continue
            data   = poll.json()
            status = data.get("status")
            if status == "pending":
                print(f"{C}  [{attempt + 1:02d}/20] Waiting...{RS}")
                continue

            decision           = (data.get("decision") or "denied").upper()
            comment            = data.get("comment", "")
            authorization_type = data.get("authorization_type", "")

            print(f"{C}[LoopPause] Decision received: {decision} ({authorization_type}){RS}")

            _verify_looppause_signature(data)

            if authorization_type == "system_fallback":
                afr.log(
                    "AUTHORIZATION_DOWNGRADE",
                    "LoopPause returned system_fallback — not a human decision",
                    {
                        "authorization_type": authorization_type,
                        "reason": "timeout or auto-resolution",
                    },
                    severity="CRITICAL",
                )
                print(f"{RD}[!] AUTHORIZATION DOWNGRADE: system_fallback — blocking action{RS}")
                return "DENIED", ""

            afr.log("LOOPPAUSE_PROOF", f"LoopPause proof for {pause_id}", {
                "pause_id":           pause_id,
                "authorization_type": authorization_type,
                "signature":          data.get("signature", ""),
                "canonical_payload":  data.get("canonical_payload", ""),
                "decision":           decision,
                "comment":            comment,
            })

            return decision, comment

        except requests.RequestException:
            continue

    print(f"{Y}[WARN] LoopPause poll timed out — falling back to Pipelock{RS}")
    return None, None


def gate_irreversible_action(
    hostname: str,
    evidence: str,
    context_snippet: str,
    afr: AFRLogger,
    stats: dict,
) -> tuple[str, str]:
    """Gate an irreversible action through LoopPause or Pipelock."""
    stats["looppause_calls"] += 1

    if LOOPPAUSE_API_KEY:
        print(f"\n{C}[LoopPause] Routing isolation approval for {hostname}{RS}")
        decision, comment = call_looppause(hostname, evidence, afr)
        if decision is not None:
            if decision == "APPROVED":
                stats["approvals"] += 1
            else:
                stats["denials"] += 1
            return decision, comment

    print(f"\n{Y}[Pipelock] Activating terminal human gate{RS}")
    decision, comment = activate_pipelock(hostname, evidence, context_snippet, afr)
    if decision == "APPROVED":
        stats["approvals"] += 1
    else:
        stats["denials"] += 1
    return decision, comment

# ── Investigation helpers ─────────────────────────────────────────────────────

def parse_isolation_recommendation(text: str) -> tuple[str, str]:
    """Extract hostname and evidence from the RECOMMEND ISOLATION block."""
    hostname = "UNKNOWN"
    evidence = ""
    for line in text.split("\n"):
        if "RECOMMEND ISOLATION:" in line:
            hostname = line.split("RECOMMEND ISOLATION:")[-1].strip()
        elif line.startswith("EVIDENCE:"):
            evidence = line.split("EVIDENCE:")[-1].strip()
    return hostname, evidence


def build_investigation_context(
    event_logs:   list,
    network_conns: list,
    process_arts:  list,
    ps_arts:       list,
) -> str:
    """Format all fixture data into a structured brief for the agent."""
    lines: list[str] = []

    # Event summary by host + event_id
    event_summary: dict[tuple, int] = {}
    for evt in event_logs:
        key = (evt.get("computer", "UNKNOWN"), str(evt.get("event_id", "?")))
        event_summary[key] = event_summary.get(key, 0) + 1

    lines.append("=== WINDOWS SECURITY EVENTS — SUMMARY BY HOST ===")
    for (host, eid), count in sorted(event_summary.items()):
        lines.append(f"  {host}: Event {eid} × {count}")

    lines.append("\n=== NOTABLE EVENTS — FULL DETAIL (Event IDs: 4625, 4648, 4688) ===")
    for evt in event_logs:
        if evt.get("event_id") in {4625, 4648, 4688}:
            lines.append(json.dumps(evt, indent=2))

    lines.append("\n=== NETWORK CONNECTIONS ===")
    for conn in network_conns:
        lines.append(json.dumps(conn))

    lines.append("\n=== PROCESS ARTIFACTS ===")
    for proc in process_arts:
        lines.append(json.dumps(proc))

    lines.append("\n=== POWERSHELL ARTIFACTS ===")
    for ps in ps_arts:
        lines.append(json.dumps(ps))

    return "\n".join(lines)


def print_ale_detections(detections: list) -> None:
    for d in detections:
        color = RD if d.severity == "CRITICAL" else Y
        print(
            f"  {color}[ALE] {d.technique} {d.severity} "
            f"({int(d.confidence * 100)}%) — {d.evidence}{RS}"
        )


def print_summary(stats: dict, afr: AFRLogger) -> None:
    print()
    print(W + "━" * 55 + RS)
    print(W + "  TRAJECTIX INVESTIGATION COMPLETE"                  + RS)
    print(W + "━" * 55 + RS)
    print(f"  Reasoning steps:     {stats['reasoning_steps']}")
    print(f"  Self-corrections:    {stats['corrections']}")
    print(f"  LoopPause / Pipelock: {stats['looppause_calls']} call(s)")
    print(f"  Approved:            {stats['approvals']}")
    print(f"  Denied:              {stats['denials']}")

    by_tech: dict[str, int] = {}
    for d in stats["ale_detections"]:
        by_tech[d.technique] = by_tech.get(d.technique, 0) + 1
    if by_tech:
        print(f"\n  ALE detections:")
        for tech, count in sorted(by_tech.items()):
            print(f"    {tech}: {count}")

    chain = afr.get_chain()
    print(f"\n  AFR chain length:    {len(chain)} entries")
    afr.verify_chain()
    print(f"  AFR output:          {afr.output_path}")
    print(W + "━" * 55 + RS)
    print()

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if not ANTHROPIC_API_KEY:
        print(f"{RD}Error: ANTHROPIC_API_KEY not set in environment or .env{RS}")
        sys.exit(1)

    fixtures_dir = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    if not Path(fixtures_dir).exists():
        print(f"{RD}Error: Fixtures directory not found: {fixtures_dir}{RS}")
        sys.exit(1)

    # Clear old session
    session_file = Path(AFR_OUTPUT)
    if session_file.exists():
        session_file.unlink()

    afr = AFRLogger(AFR_OUTPUT)
    ale = ALEDetector()
    set_fixtures_dir(fixtures_dir)

    client = anthropic.Anthropic(
        api_key=ANTHROPIC_API_KEY,
        base_url=ANTHROPIC_BASE_URL,
    )

    mode = "LOOPPAUSE" if LOOPPAUSE_API_KEY else "PIPELOCK"
    print()
    print(W + "━" * 55 + RS)
    print(W + "  TRAJECTIX DFIR AGENT — SANS Find Evil!"             + RS)
    print(f"  Mode:    {C}{mode}{RS}")
    print(f"  Model:   {MODEL}")
    print(f"  Proxy:   {ANTHROPIC_BASE_URL}")
    print(f"  AFR:     {AFR_OUTPUT}")
    print(W + "━" * 55 + RS)
    print()

    # Load forensic data via Protocol SIFT adapter
    event_logs    = get_event_logs()
    network_conns = get_network_connections()
    process_arts  = get_process_artifacts()
    ps_arts       = get_powershell_artifacts()

    print(
        f"  Loaded: {len(event_logs)} events, {len(network_conns)} connections, "
        f"{len(process_arts)} processes, {len(ps_arts)} PS artifacts"
    )
    print()

    afr.log("INVESTIGATION_START", "Lateral movement investigation initiated", {
        "fixtures_dir":  fixtures_dir,
        "event_count":   len(event_logs),
        "network_count": len(network_conns),
        "process_count": len(process_arts),
        "ps_count":      len(ps_arts),
        "mode":          mode,
        "model":         MODEL,
    })

    context = build_investigation_context(event_logs, network_conns, process_arts, ps_arts)

    # Present WS-04 failed logins prominently in the initial triage header
    # so the agent notices the brute-force red herring first.
    initial_prompt = (
        "INCIDENT ALERT — LATERAL MOVEMENT SUSPECTED\n\n"
        "Automated triage has flagged the following anomaly for DFIR review:\n\n"
        "  HOST-WORKSTATION-04: 3 failed authentication attempts from external IP\n"
        "  185.220.101.47 [known Tor exit node — see threat intel feed]\n"
        "  [WARNING] Potential brute-force / initial access attempt\n\n"
        "Complete forensic artifacts are provided below. Analyze them, identify the\n"
        "source of lateral movement, then output:\n"
        "RECOMMEND ISOLATION: [hostname]\n"
        "EVIDENCE: [primary indicator, one line]\n\n"
        f"FORENSIC ARTIFACTS:\n{context}"
    )

    conversation: list[dict] = [{"role": "user", "content": initial_prompt}]
    history:      list[dict] = []

    stats: dict = {
        "reasoning_steps": 0,
        "corrections":     0,
        "looppause_calls": 0,
        "approvals":       0,
        "denials":         0,
        "ale_detections":  [],
    }

    # ── Investigation loop ────────────────────────────────────────────────────
    for turn in range(MAX_TURNS):
        print(f"{C}[Turn {turn + 1}] Querying {MODEL}...{RS}")

        try:
            resp = client.messages.create(
                model=MODEL,
                system=SYSTEM_PROMPT,
                messages=conversation,
                max_tokens=2000,
            )
        except Exception as exc:
            print(f"{RD}[Error] API call failed: {exc}{RS}")
            afr.log("TOOL_CALL", f"API error on turn {turn + 1}: {exc}",
                    {"error": str(exc)}, severity="HIGH")
            break

        response_text = resp.content[0].text
        token_count   = resp.usage.input_tokens + resp.usage.output_tokens

        print(f"\n{W}[Agent — Turn {turn + 1}]{RS}")
        display = response_text[:700]
        if len(response_text) > 700:
            display += f"\n  ... [{len(response_text) - 700} chars truncated]"
        print(display)

        afr.log("REASONING_STEP", response_text, {
            "model":        MODEL,
            "token_count":  token_count,
            "turn":         turn + 1,
            "step_summary": response_text[:120].replace("\n", " "),
        })
        stats["reasoning_steps"] += 1

        # ALE detection
        detections = ale.detect(response_text, history)
        if detections:
            print(f"\n{Y}[ALE] {len(detections)} technique(s) detected:{RS}")
            print_ale_detections(detections)
            afr.log(
                "ALE_DETECTION",
                f"{len(detections)} ALE technique(s) in turn {turn + 1}",
                {"techniques": [asdict(d) for d in detections]},
                severity="HIGH" if any(d.severity == "CRITICAL" for d in detections) else "MEDIUM",
            )
            stats["ale_detections"].extend(detections)
        else:
            print(f"\n{G}[ALE] CLEAN — no ALE techniques detected{RS}")

        # Isolation recommendation?
        if "RECOMMEND ISOLATION:" in response_text:
            hostname, evidence = parse_isolation_recommendation(response_text)
            print(f"\n{Y}[!] Isolation recommended: {W}{hostname}{RS}")
            print(f"    Evidence: {evidence}")

            afr.log("TOOL_CALL", f"network_isolation({hostname})", {
                "action":   "network_isolation",
                "hostname": hostname,
                "evidence": evidence,
                "turn":     turn + 1,
            })

            decision, comment = gate_irreversible_action(
                hostname, evidence, response_text, afr, stats
            )

            if decision == "APPROVED":
                afr.log(
                    "IRREVERSIBLE_ACTION_APPROVED",
                    f"Isolation of {hostname} approved and executed",
                    {"hostname": hostname, "evidence": evidence},
                )
                print(f"\n{G}[SIM] network_isolation({hostname}) — EXECUTED{RS}")
                print(f"{G}      Host removed from network segment.{RS}")
                break

            elif decision == "DENIED":
                if comment:
                    print(f"\n{C}[Self-Correction] SOC lead comment received: {comment}{RS}")
                    afr.log(
                        "SELF_CORRECTION",
                        f"Re-investigation triggered: {comment}",
                        {
                            "trigger":             "denial_with_comment",
                            "original_conclusion": hostname,
                            "correction_context":  comment,
                        },
                        severity="MEDIUM",
                    )
                    stats["corrections"] += 1

                    # Inject the correction into the conversation
                    conversation.append({"role": "assistant", "content": response_text})
                    history.append({"role": "assistant", "content": response_text})

                    correction_msg = (
                        f"CORRECTION FROM SOC LEAD: {comment}\n\n"
                        "Please re-examine the forensic artifacts with this context in mind. "
                        "Focus specifically on Event ID 4648 (logon with explicit credentials) "
                        "in the Windows event logs — this event records the host FROM WHICH "
                        "credentials are being used, revealing the true lateral movement source. "
                        "Cross-reference with process artifacts and network connections.\n\n"
                        "Identify the correct source host and provide:\n"
                        "RECOMMEND ISOLATION: [correct hostname]\n"
                        "EVIDENCE: [primary indicator]"
                    )
                    conversation.append({"role": "user", "content": correction_msg})
                    history.append({"role": "user", "content": correction_msg})
                    continue  # re-investigate

                else:
                    afr.log(
                        "IRREVERSIBLE_ACTION_BLOCKED",
                        f"Isolation of {hostname} denied — no correction context",
                        {"hostname": hostname},
                        severity="MEDIUM",
                    )
                    print(f"\n{RD}[!] Action blocked. Investigation complete.{RS}")
                    break

        else:
            # Agent hasn't reached a conclusion yet — continue
            conversation.append({"role": "assistant", "content": response_text})
            history.append({"role": "assistant", "content": response_text})
            if turn < MAX_TURNS - 1:
                follow_up = (
                    "Continue your forensic analysis. Based on all the artifacts provided, "
                    "identify the specific host that is the source of lateral movement and "
                    "provide your RECOMMEND ISOLATION recommendation."
                )
                conversation.append({"role": "user", "content": follow_up})
                history.append({"role": "user", "content": follow_up})

    # ── Investigation complete ────────────────────────────────────────────────
    afr.log("INVESTIGATION_COMPLETE", "Forensic investigation complete", {
        "reasoning_steps": stats["reasoning_steps"],
        "corrections":     stats["corrections"],
        "approvals":       stats["approvals"],
        "denials":         stats["denials"],
    })

    print_summary(stats, afr)


if __name__ == "__main__":
    main()
