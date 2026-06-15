"""
Protocol SIFT Integration Adapter

In production this module calls Protocol SIFT's MCP tool interface to
retrieve live forensic data from the investigation environment:

    sift_evtx_parse      → get_event_logs()
    netstat_analyzer     → get_network_connections()
    process_tree         → get_process_artifacts()
    ps_artifact_parser   → get_powershell_artifacts()

In the hackathon demo, fixture JSON files replicate Protocol SIFT tool
output structure so the investigation narrative runs identically to a
live deployment — only the data source differs.
"""
import json
from pathlib import Path


_FIXTURES_DIR: Path | None = None


def set_fixtures_dir(path: str) -> None:
    """Set the fixtures directory. Must be called before any get_* function."""
    global _FIXTURES_DIR
    _FIXTURES_DIR = Path(path)


def _load(filename: str) -> list:
    if _FIXTURES_DIR is None:
        raise RuntimeError(
            "Fixtures directory not set. Call set_fixtures_dir() first."
        )
    filepath = _FIXTURES_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(f"Fixture not found: {filepath}")
    with filepath.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def get_event_logs(host: str = "all") -> list[dict]:
    """
    Return parsed Windows Security event log entries.

    Production: Protocol SIFT sift_evtx_parse tool via MCP
    Demo:       fixtures/windows_event_logs.json

    Fields: event_id, timestamp, computer, channel, subject,
            account, logon_type, source_network, target_server, process
    """
    entries = _load("windows_event_logs.json")
    if host == "all":
        return entries
    return [e for e in entries if e.get("computer", "") == host]


def get_network_connections(host: str = "all") -> list[dict]:
    """
    Return network connection records.

    Production: Protocol SIFT netstat_analyzer tool via MCP
    Demo:       fixtures/network_connections.json

    Fields: timestamp, source_host, source_ip, source_port,
            destination_ip, destination_port, protocol, state, process
    """
    entries = _load("network_connections.json")
    if host == "all":
        return entries
    return [e for e in entries if e.get("source_host", "") == host]


def get_process_artifacts(host: str = "all") -> list[dict]:
    """
    Return process execution tree records.

    Production: Protocol SIFT process_tree tool via MCP
    Demo:       fixtures/process_artifacts.json

    Fields: timestamp, computer, pid, parent_pid, process_name,
            command_line, image_path, user, integrity_level
    """
    entries = _load("process_artifacts.json")
    if host == "all":
        return entries
    return [e for e in entries if e.get("computer", "") == host]


def get_powershell_artifacts(host: str = "all") -> list[dict]:
    """
    Return PowerShell execution artifacts.

    Production: Protocol SIFT ps_artifact_parser tool via MCP
    Demo:       fixtures/powershell_artifacts.json

    Fields: timestamp, computer, event_id, script_block_id,
            script_block_text, encoded_command, decoded_command
    """
    entries = _load("powershell_artifacts.json")
    if host == "all":
        return entries
    return [e for e in entries if e.get("computer", "") == host]
