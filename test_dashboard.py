"""dashboard.py 测试：起 server → 验证 API → 截图目检。"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "/Users/zhj/hexstrike-ai")
import memory
import dashboard

P = "/tmp/dash-demo.json"
if os.path.exists(P):
    os.remove(P)

snap = memory.AssetSnapshot(P).load()
snap.upsert_asset("https://example.com:8443", tags=["prod"], source="nuclei")
snap.upsert_asset("192.0.2.10:80", protocol="http", tags=["dmz"])
a = snap.data["assets"]["example.com|8443|https"]
a["findings"] = [
    {"id": "x1", "type": "xss", "severity": "high", "verdict": "confirmed",
     "evidence_sha256": "a" * 64, "repro_command": "curl -sS https://example.com:8443/echo?id=X",
     "matched_at": "https://example.com:8443/echo?id=1", "at": "2026-09-15T00:00:00+00:00"},
    {"id": "x2", "type": "sqli", "severity": "critical", "verdict": "confirmed",
     "evidence_sha256": "b" * 64, "repro_command": "curl -sS https://example.com:8443/sql?id=1",
     "matched_at": "https://example.com:8443/sql?id=1", "at": "2026-09-15T00:00:00+00:00"},
    {"id": "x3", "type": "tls_misconfig", "severity": "medium", "verdict": "unverifiable",
     "evidence_sha256": "c" * 64, "repro_command": "openssl s_client -connect ...",
     "matched_at": "example.com:8443", "at": "2026-09-15T00:00:00+00:00"},
]
snap._recompute_risk(a)
snap.save()

r = dashboard.start_dashboard(P, port=8799, open_browser=False)
print("start:", r)
assert r["status"] == "running"

html = urllib.request.urlopen("http://127.0.0.1:8799/").read().decode("utf-8")
assert "HexStrike 资产仪表盘" in html
stats = json.load(urllib.request.urlopen("http://127.0.0.1:8799/api/stats"))
assets = json.load(urllib.request.urlopen("http://127.0.0.1:8799/api/assets"))
print("stats:", stats)
print("assets:", [(x["target"], x["risk_level"]) for x in assets])
assert stats["total_assets"] == 2 and stats["total_confirmed"] == 2
assert stats["by_risk"]["critical"] == 1 and assets[0]["pending_review"] == 1
try:
    urllib.request.urlopen("http://127.0.0.1:8799/nope")
    raise AssertionError("expected 404")
except urllib.error.HTTPError as e:
    assert e.code == 404

# 复用同端口 → created=False
r2 = dashboard.start_dashboard(P, port=8799, open_browser=False)
assert r2["created"] is False
dashboard.stop_dashboard(port=8799)
r3 = dashboard.start_dashboard(P, port=8799, open_browser=False)
assert r3["created"] is True
dashboard.stop_dashboard(port=8799)

# 截图目检（headless Chrome）
chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if os.path.exists(chrome):
    d2 = dashboard.start_dashboard(P, port=8799, open_browser=False)
    shot = "/tmp/dash.png"
    subprocess.run([chrome, "--headless", "--disable-gpu", "--screenshot=" + shot,
                    "--window-size=1280,900", "--hide-scrollbars",
                    "http://127.0.0.1:8799/"], check=True, timeout=60)
    print("screenshot:", shot, os.path.getsize(shot), "bytes")
    dashboard.stop_dashboard(port=8799)
else:
    print("(no Chrome, skip screenshot)")

os.remove(P)
print("DASHBOARD TEST OK")