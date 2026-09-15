"""memory.py 单元测试：normalize/dedup/upsert/risk/query/report。"""
import os
import sys
import tempfile
import time

sys.path.insert(0, "/Users/zhj/hexstrike-ai")
import memory as M

# --- split_target / dedup_key ---
cases = [
    ("https://Example.com:8443/x?a=1", 8443, "https", "example.com", None),
    ("example.com", 0, "", "example.com", None),
    ("192.0.2.10:443", 0, "", "192.0.2.10", "ip"),
    ("http://app.server.host", 0, "", "app.server.host", None),
    ("[2001:db8::1]:443", 0, "", "2001:db8::1", "ip"),
    ("www.测试.cn", 0, "", "www.xn--0zwm56d.cn", None),   # punycode
]
ok = True
for raw, port, proto, exp_host, exp_kind in cases:
    a = M.split_target(raw, port=port, protocol=proto)
    if exp_kind == "ip":
        assert a["ip"] == exp_host, f"{raw}: ip={a['ip']}"
    elif "xn--" in exp_host:
        assert a["domain"] == exp_host, f"{raw}: domain={a['domain']}"
    else:
        assert a["host"] == exp_host, f"{raw}: host={a['host']}"
    if not port:
        assert a["protocol"] in ("", "https", "http")
print("split_target: OK")

key1 = M.dedup_key({"domain": "example.com", "port": 443, "protocol": "https"})
key2 = M.dedup_key({"ip": "192.0.2.10", "port": 443, "protocol": "https"})
assert key1 == "example.com|443|https" and key2 == "192.0.2.10|443|https"
print("dedup_key: OK")

# --- upsert（借 temp 快照避免污染库）---
with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "snap.json")
    s = M.AssetSnapshot(p).load()
    a1 = s.upsert_asset("https://example.com", tags=["prod"], source="nuclei")
    assert a1["key"] == "example.com|443|https" and a1["first_seen"] == a1["last_seen"]
    time.sleep(0.01)
    a2 = s.upsert_asset("example.com:443", tags=["auth"], source="nuclei")   # dup
    assert a2["key"] == a1["key"] and a2["first_seen"] == a1["first_seen"]
    assert a2["last_seen"] >= a1["last_seen"] and set(a2["tags"]) == {"prod", "auth"}
    print("upsert 合并(first_seen 保留 / last_seen 刷新 / tags 并集): OK")

    # --- record_verifications：三态对风险的影响 ---
    results = [
        {"id": "f1", "type": "xss", "severity": "high", "target": "example.com",
         "matched_at": "https://example.com/echo?id=1",
         "verdict": {"verdict": "confirmed", "evidence_sha256": "abc", "repro_command": "curl ..."}},
        {"id": "f2", "type": "open_port", "severity": "low", "target": "example.com",
         "matched_at": "example.com:8443",
         "verdict": {"verdict": "refuted", "evidence_sha256": "def", "repro_command": "nc ..."}},
        {"id": "f3", "type": "sqli", "severity": "critical", "target": "example.com",
         "matched_at": "https://example.com/sql?id=1",
         "verdict": {"verdict": "unverifiable", "evidence_sha256": "", "repro_command": ""}},
    ]
    res = s.record_verifications(results)
    assert res["assets_created"] >= 1, res
    a = s.data["assets"]["example.com|443|https"]
    assert a["risk_level"] == "high"                     # confirmed high → risk high
    assert a["vuln_count"] == 1 and a["pending_review"] == 1
    a8443 = s.data["assets"]["example.com|8443|"]
    assert a8443["risk_level"] == "normal"               # refuted only → normal
    assert a8443["vuln_count"] == 0
    print("三态→风险演算(confirmed 抬级 / refuted 不计 / unverifiable 待复核): OK")

    # 重复验证 verdict 变化留痕
    results2 = [{"id": "f3", "type": "sqli", "severity": "critical", "target": "example.com",
                 "matched_at": "https://example.com/sql?id=1",
                 "verdict": {"verdict": "confirmed", "evidence_sha256": "cc", "repro_command": "c"}}]
    s.record_verifications(results2)
    f3 = next(f for f in s.data["assets"]["example.com|443|https"]["findings"] if f["id"] == "f3")
    assert f3["verdict"] == "confirmed" and f3["previous_verdict"] == "unverifiable"
    assert s.data["assets"]["example.com|443|https"]["risk_level"] == "critical"  # now critical+high
    print("verdict 变化留痕 previous_verdict + 风险重算: OK")

    # --- query / report ---
    q = s.query(q="example.com")
    assert len(q) == 2
    qr = s.query(risk_level="critical")
    assert len(qr) == 1 and qr[0]["key"].startswith("example.com|443")
    md = s.to_markdown(overview_only=True)
    assert "风险分布" in md and "high" in md
    st = s.stats()
    assert st["total_assets"] == 2 and st["pending_review"] == 0
    print("query 过滤 + markdown 报告 + stats: OK")

print("\nALL MEMORY TESTS PASSED")