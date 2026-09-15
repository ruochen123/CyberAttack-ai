"""Agent 任务端到端：POST /api/jobs type=agent → claude -p headless → 工具调用 → done。"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/Users/zhj/hexstrike-ai")
import dashboard

P = "/tmp/agent-test.json"
if os.path.exists(P):
    os.remove(P)
dashboard.start_dashboard(P, port=8796, open_browser=False)


def req(m, p, b=None):
    data = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:8796{p}", data=data, method=m,
                               headers={"Content-Type": "application/json"} if data else {})
    try:
        resp = urllib.request.urlopen(r)
        return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


goal = ("调用 verify_findings 工具验证这条 finding："
        '{"findings":[{"target":"127.0.0.1","type":"open_port","source_tool":"nmap",'
        '"matched_at":"127.0.0.1:59999","severity":"low","raw":"closed"}]}；用一句中文总结结论。')
st, j = req("POST", "/api/jobs", {"type": "agent", "goal": goal})
assert st == 202, (st, j)
jid = j["job_id"]
js = None
deadline = time.time() + 300
while time.time() < deadline:
    st, js = req("GET", "/api/jobs/" + jid)
    if js["status"] in ("done", "error", "cancelled"):
        break
    time.sleep(1)

print("status:", js["status"], "| error:", js.get("error", ""))
print("log 行数:", len(js.get("log", [])))
log = "\n".join(js.get("log", []))
print("含 Agent 头:", "Claude Agent" in log)
print("含 verify_findings 工具:", "verify_findings" in log)
print("tail:", log[-240:].replace("\n", " / "))
assert js["status"] == "done", js
assert "verify_findings" in log
print("AGENT JOB OK")
dashboard.stop_dashboard(port=8796)
if os.path.exists(P):
    os.remove(P)