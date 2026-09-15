"""Web 控制台端到端：POST /api/jobs(verify) → 轮询 → 快照写入 → 资产操作。"""
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

P = "/tmp/console-test.json"
if os.path.exists(P):
    os.remove(P)
d = dashboard.start_dashboard(P, port=8798, open_browser=False)
assert d["status"] == "running"


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:8798{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"} if data else {})
    try:
        resp = urllib.request.urlopen(r)
        return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


# 1) 发起 verify job（对本地 echo 目标真实发请求）
finding = [{"target": base, "type": "xss", "source_tool": "dalfox",
            "matched_at": base + "/echo?id=1", "severity": "high", "raw": "x"}]
st, j = req("POST", "/api/jobs", {"type": "verify", "findings_json": json.dumps(finding)})
assert st == 202, (st, j)
jid = j["job_id"]
js = None
for _ in range(60):
    st, js = req("GET", "/api/jobs/" + jid)
    if js["status"] in ("done", "error", "cancelled"):
        break
    time.sleep(0.2)
assert js["status"] == "done", js
print("job:", js["kind"], js["status"], "| confirmed:", js["result"]["confirmed"])
assert js["result"]["confirmed"] >= 1

# 2) 扫描结果自动写入快照
st, snap = req("GET", "/api/stats")
assert snap["total_assets"] >= 1 and snap["total_confirmed"] >= 1, snap
print("快照资产:", snap["total_assets"], "确认漏洞:", snap["total_confirmed"])

# 3) 资产操作：加标签 / 删除
st, assets = req("GET", "/api/assets")
key = assets[0]["key"]
st, _ = req("POST", "/api/assets/tags", {"keys": [key], "add": ["redteam"]})
st, assets = req("GET", "/api/assets")
assert "redteam" in assets[0]["tags"]
st, r = req("POST", "/api/assets/delete", {"keys": [key]})
assert r["deleted"] == 1
st, snap = req("GET", "/api/stats")
print("delete 后资产:", snap["total_assets"])

# 4) 报告导出
st, rep = req("GET", "/api/report?full=1")
assert "资产基线" in rep["report"]
print("报告导出 OK (", len(rep["report"]), "chars )")

dashboard.stop_dashboard(port=8798)
srv.shutdown()
os.remove(P)
print("CONSOLE TEST OK")