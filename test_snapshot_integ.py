"""集成冒烟：真实 verify_findings 输出结构 → snapshot_update → query/report。"""
import os
import sys

sys.path.insert(0, "/Users/zhj/hexstrike-ai")
import memory as M

P = "/tmp/hx-snapshot.json"
if os.path.exists(P):
    os.remove(P)

# 结构与真实 MCP verify_findings 返回一致
results = [
    {"id": "a1", "type": "xss", "severity": "high", "target": "127.0.0.1:18088",
     "source_tool": "dalfox", "matched_at": "http://127.0.0.1:18088/echo?id=1",
     "verdict": {"verdict": "confirmed", "repro_command": "curl -sS 'http://127.0.0.1:18088/echo?id=...'",
                 "evidence": "echo:<b>HXVx</b>", "evidence_sha256": "d7e9...", "detail": "原样反射", "latency_ms": 27}},
    {"id": "a2", "type": "exposed_path", "severity": "high", "target": "127.0.0.1:18088",
     "source_tool": "ffuf", "matched_at": "http://127.0.0.1:18088/secret.txt",
     "verdict": {"verdict": "confirmed", "repro_command": "curl ...", "evidence": "...",
                 "evidence_sha256": "af4a...", "detail": "非软404", "latency_ms": 35}},
    {"id": "a3", "type": "open_port", "severity": "low", "target": "127.0.0.1",
     "source_tool": "nmap", "matched_at": "127.0.0.1:59999",
     "verdict": {"verdict": "refuted", "repro_command": "nc -vz ... 59999", "evidence": "refused",
                 "evidence_sha256": "ed3e...", "detail": "closed", "latency_ms": 12}},
]

r1 = M.snapshot_update(results, P)
print("第1次:", r1)
assert r1["total_assets"] == 2 and r1["assets_created"] == 2, r1
assert r1["findings_new"] == 3, r1          # 3 条 finding 全为新写
assert r1["assets_updated"] == 1            # a2 复用 a1 同服务资产

q = M.query_assets(query="18088", snapshot_path=P)
print("query '18088':", q["total"], "assets")
assert q["total"] == 1

# 同批再喂一次 → upsert 去重，不新增资产/finding
r2 = M.snapshot_update(results, P)
print("第2次(应去重):", r2)
assert r2["total_assets"] == 2 and r2["assets_created"] == 0 and r2["findings_new"] == 0, r2

rep = M.snapshot_report("overview", P)["report"]
print("--- report 摘要 ---")
print(rep[:600])
assert "风险分布" in rep

q2 = M.query_assets(risk_level="high", snapshot_path=P)
print("risk=high:", [a["key"] for a in q2["results"]])
assert len(q2["results"]) == 1               # 18088 端口带 2 条 confirmed → high

os.remove(P)
print("\nINTEGRATION OK")