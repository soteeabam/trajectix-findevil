"""
Trajectix Agentic Flight Recorder (AFR) Logger
OCSF v1.3 aligned — Detection Finding class_uid 4001, category_uid 4

SHA-256 hash chain where every entry is cryptographically bound to its
predecessor, creating a tamper-evident chain of custody suitable for
legal and regulatory review.

Hash construction:
    content_hash  = SHA-256(content)
    previous_hash = content_hash of prior entry  ("GENESIS" for entry 1)
    chain_hash    = SHA-256(previous_hash + content_hash + timestamp)
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_SEVERITY_ID: dict[str, int] = {
    "UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3,
    "HIGH": 4, "CRITICAL": 5, "FATAL": 6,
}

_EVENT_STATUS: dict[str, str] = {
    "INVESTIGATION_START":          "New",
    "REASONING_STEP":               "In Progress",
    "ALE_DETECTION":                "In Progress",
    "TOOL_CALL":                    "In Progress",
    "TOOL_RESULT":                  "In Progress",
    "LOOPPAUSE_PAUSE":              "In Progress",
    "LOOPPAUSE_PROOF":              "In Progress",
    "AUTHORIZATION_DOWNGRADE":      "In Progress",
    "PIPELOCK_DECISION":            "In Progress",
    "SELF_CORRECTION":              "In Progress",
    "IRREVERSIBLE_ACTION_BLOCKED":  "In Progress",
    "IRREVERSIBLE_ACTION_APPROVED": "Resolved",
    "INVESTIGATION_COMPLETE":       "Resolved",
}


class AFRLogger:
    """
    Tamper-evident JSONL forensic event logger.
    Call verify_chain() after a session to confirm the chain is intact.
    """

    def __init__(self, output_path: str = "trajectix_session.jsonl") -> None:
        self.output_path = Path(output_path)
        self.step_id: int = 0
        self._last_content_hash: str = "GENESIS"

    @staticmethod
    def _sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def log(
        self,
        event_type: str,
        content: str,
        metadata: Optional[dict] = None,
        severity: str = "INFO",
    ) -> dict:
        """Append one entry to the chain and return it."""
        self.step_id += 1
        timestamp = datetime.now(timezone.utc).isoformat()

        content_hash  = self._sha256(content)
        previous_hash = self._last_content_hash
        chain_hash    = self._sha256(previous_hash + content_hash + timestamp)

        entry: dict = {
            "step_id":       self.step_id,
            "timestamp":     timestamp,
            "event_type":    event_type,
            "content":       content,
            "content_hash":  content_hash,
            "previous_hash": previous_hash,
            "chain_hash":    chain_hash,
            "metadata":      metadata or {},
            # OCSF v1.3 Detection Finding
            "class_uid":    4001,
            "category_uid": 4,
            "severity_id":  _SEVERITY_ID.get(severity.upper(), 1),
            "status":       _EVENT_STATUS.get(event_type, "In Progress"),
            "activity_id":  1,
        }

        with self.output_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self._last_content_hash = content_hash
        return entry

    def get_chain(self) -> list[dict]:
        """Return all entries as a list of dicts."""
        if not self.output_path.exists():
            return []
        entries: list[dict] = []
        with self.output_path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    try:
                        entries.append(json.loads(raw))
                    except json.JSONDecodeError:
                        pass
        return entries

    def verify_chain(self) -> bool:
        """
        Walk every entry and verify content_hash, previous_hash linkage,
        and chain_hash. Prints result. Returns True if chain is intact.
        """
        entries = self.get_chain()
        if not entries:
            print("CHAIN INTEGRITY: EMPTY (no entries)")
            return True

        prev_content_hash = "GENESIS"
        for entry in entries:
            sid = entry["step_id"]

            expected_ch = self._sha256(entry["content"])
            if expected_ch != entry["content_hash"]:
                print(f"CHAIN INTEGRITY: INVALID (content_hash mismatch at step {sid})")
                return False

            if entry["previous_hash"] != prev_content_hash:
                print(f"CHAIN INTEGRITY: INVALID (previous_hash mismatch at step {sid})")
                return False

            expected_chain = self._sha256(
                entry["previous_hash"] + entry["content_hash"] + entry["timestamp"]
            )
            if expected_chain != entry["chain_hash"]:
                print(f"CHAIN INTEGRITY: INVALID (chain_hash mismatch at step {sid})")
                return False

            prev_content_hash = entry["content_hash"]

        print(f"CHAIN INTEGRITY: VALID ({len(entries)} entries)")
        return True
