"""NL 驱动接口端到端：/api/nlp 分发 → verify(从快照)/tag/stats/scan(取消)。"""
import http.server
import json
import os
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, "/Users/zhj/hexstrike-ai")
import dashboard
import memory


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _send(self, b, c=200):
        b = b.encode()
        self.send_response(c)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        pu = urllib.parse.urlparse(self.path)
        if pu.path == "/echo":
            qs = dict(urllib.parse.parse_qsl(pu.query))
            self._send("echo:" + qs.get("id", ""))
        else:
            self._send("404", 404)

    def log_message(self, *a):
        pass


srv = socketserver.TCPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"

P = "/tmp/nlp-test.json"
if os.path.exists(P):
    os.remove(P)
snap = memory.AssetSnapshot(P).load()
snap.upsert_asset(base)
a = snap.data["assets"][f"127.0.0.1|{port}|http"]
a["findings"] = [{"id": "nlp-f1", "type": "xss", "severity": "high", "verdict": "confirmed",
                  "evidence_sha256": "a" * 64, "repro_command": "curl ...",
                  "matched_at": base + "/echo?id=1", "at": "2026-09-15T00:00:00+00:00"}]
snap._recompute_risk(a)
snap.save()
dashboard.start_dashboard(P, port=8797, open_browser=False)


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:8797{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"} if data else {})
    try:
        resp = urllib.request.urlopen(r)
        return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


# 1) scan：返回 202 job，立即取消避免真扫
st, r = req("POST", "/api/nlp", {"text": "扫描 http://127.0.0.1:9 的高危 xss"})
assert st == 202 and r["job_id"], (st, r)
req("POST", f"/api/jobs/{r['job_id']}/cancel")
print("scan 指令 → job", r["job_id"], "OK（已取消）")

# 2) verify：从快照取 finding 复验本地 echo → confirmed
st, v = req("POST", "/api/nlp", {"text": f"验证 {base}"})
assert st == 202, (st, v)
jid = v["job_id"]
for _ in range(60):
    st, js = req("GET", "/api/jobs/" + jid)
    if js["status"] in ("done", "error", "cancelled"):
        break
    time.sleep(0.2)
assert js["status"] == "done", js
assert js["result"]["confirmed"] >= 1, js
print("verify 指令 → confirmed", js["result"]["confirmed"], "OK")

# 3) tag：给匹配资产加标签
st, t = req("POST", "/api/nlp", {"text": "给 127.0.0.1 加 web 标签"})
assert t.get("ok") and t["matched"], t
assert "web" in dashboard._snapshot_db.data["assets"][t["matched"][0]]["tags"]
print("tag 指令 →", t["message"], "OK")

# 4) stats
st, s = req("POST", "/api/nlp", {"text": "资产统计"})
assert s.get("ok") and s["stats"]["total_assets"] >= 1
print("stats 指令 → 资产", s["stats"]["total_assets"], "OK")

dashboard.stop_dashboard(port=8797)
srv.shutdown()
os.remove(P)
print("NL API TEST OK")