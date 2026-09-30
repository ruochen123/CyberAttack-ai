"""OAST — Out-of-Band Application Security Testing via interactsh (改造⑥-P0).

Manages a locally-spawned interactsh-client as a background process:
  - oast_start:  register a unique polling domain, return it for use in blind payloads
  - oast_poll:   fetch any DNS/HTTP interactions received on the domain
  - oast_stop:   terminate the client

The client reaches interact.sh through the local Clash proxy so it can poll
callbacks from this machine (bound to the interact.sh service, not the target).
"""
import json
import os
import subprocess
import time
import uuid
from typing import Any, Dict

CLIENT = os.path.expanduser("~/.local/bin/interactsh-client")
_STATE_DIR = "/tmp"
PROXY_DEFAULT = "http://127.0.0.1:7897"

_SESSIONS: Dict[str, Dict[str, Any]] = {}  # oast_id -> {proc, domain, jsonl, log, start}


def oast_start(server: str = "interact.sh", proxy: str = PROXY_DEFAULT, timeout: int = 40) -> Dict[str, Any]:
    oast_id = uuid.uuid4().hex[:8]
    jsonl = os.path.join(_STATE_DIR, f"oast_{oast_id}.jsonl")
    log = os.path.join(_STATE_DIR, f"oast_{oast_id}.log")
    payload_file = os.path.join(_STATE_DIR, f"oast_{oast_id}_payload.txt")
    cmd = [CLIENT, "-json", "-o", jsonl, "-ps", "-psf", payload_file,
           "-auth=false", "-duc", "-pi", "3"]
    if server and server != "interact.sh":
        cmd += ["-s", server]
    env = dict(os.environ)
    if proxy:
        env["https_proxy"] = proxy
        env["http_proxy"] = proxy
    logf = open(log, "w", encoding="utf-8")
    try:
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env)
    except Exception as e:
        logf.close()
        return {"success": False, "error": f"spawn failed: {type(e).__name__}: {e}"}
    _SESSIONS[oast_id] = {"proc": proc, "jsonl": jsonl, "log": log, "payload_file": payload_file,
                          "server": server or "oast.*", "start": time.time()}

    domain = None
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            tail = open(log, errors="replace").read()
            return {"success": False, "error": "client exited early", "log_tail": tail[-1500:]}
        # payload-store file is written by the client as soon as payloads are registered
        if os.path.exists(payload_file):
            with open(payload_file, errors="replace") as f:
                lines = f.read().splitlines()
            if lines and lines[0].strip():
                domain = lines[0].strip()
                break
        time.sleep(0.5)
    if not domain:
        return {"success": False, "error": "no payload domain observed",
                "log_tail": open(log, errors="replace").read()[-1500:]}
    _SESSIONS[oast_id]["domain"] = domain
    return {
        "success": True,
        "oast_id": oast_id,
        "domain": domain,
        "jsonl": jsonl,
        "note": "Drop this domain into blind payloads (SSRF/XXE/XSS), then call oast_poll to fetch callbacks.",
    }


def _active() -> list:
    return [k for k, v in _SESSIONS.items() if v["proc"].poll() is None]


def oast_poll(oast_id: str = "", limit: int = 100) -> Dict[str, Any]:
    if not oast_id:
        active = _active()
        if not active:
            return {"success": False, "error": "no active oast session; call oast_start first"}
        oast_id = active[0]
    if oast_id not in _SESSIONS:
        return {"success": False, "error": f"unknown oast_id {oast_id}"}
    jsonl = _SESSIONS[oast_id]["jsonl"]
    interactions = []
    if os.path.exists(jsonl):
        with open(jsonl, errors="replace") as f:
            for ln in f.read().splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    interactions.append(json.loads(ln))
                except Exception:
                    continue
    return {
        "success": True,
        "oast_id": oast_id,
        "domain": _SESSIONS[oast_id].get("domain", ""),
        "interaction_count": len(interactions),
        "interactions": interactions[-limit:],
    }


def oast_stop(oast_id: str = "") -> Dict[str, Any]:
    if not oast_id:
        active = _active()
        if not active:
            return {"success": False, "error": "no active oast session"}
        oast_id = active[0]
    if oast_id not in _SESSIONS:
        return {"success": False, "error": f"unknown oast_id {oast_id}"}
    proc = _SESSIONS.pop(oast_id)["proc"]
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    return {"success": True, "oast_id": oast_id, "stopped": True}