#!/usr/bin/env python3
"""HexStrike 轻量跨任务记忆（改造③）— 单 JSON 文件资产快照。

设计见 docs/cross-task-memory-design.md。借鉴 CyberStrikeAI 的资产规范化/服务级
去重/upsert 合并/风险演算，但保持轻量：一个可人读可审计的 JSON 文件，无 DB。

与证据层（verifiers.py）衔接：`record_verifications()` 把 verify_findings 的三态
结果写进快照，confirmed 抬风险、refuted 留历史不计、unverifiable 待复核。
"""

import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone

SEVERITY_ORDER = ("critical", "high", "medium", "low")

DEFAULT_SNAPSHOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "ai-security-snapshot.json")

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ============================================================================
# 规范化与去重（借鉴 CyberStrikeAI normalizeAsset / assetDedupKey）
# ============================================================================

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _to_ascii_host(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def split_target(raw: str, port: int = 0, protocol: str = "") -> dict:
    """从 URL / host[:port] 拆出 {host, domain, ip, port, protocol}。规则与文档一致。"""
    raw = (raw or "").strip()
    out = {"host": "", "domain": "", "ip": "", "port": port or 0, "protocol": protocol}
    if not raw:
        return out
    if "://" in raw:
        m = re.match(r"^([a-zA-Z]+)://([^/?#]+)", raw)
        if m:
            protocol = (protocol or m.group(1)).lower()
            raw_host = m.group(2)
            if ":" in raw_host and not raw_host.startswith("["):
                raw_host, _, p = raw_host.rpartition(":")
                if p.isdigit():
                    port = int(p)
            elif raw_host.startswith("[") and "]" in raw_host:
                raw_host, p = raw_host[1:].split("]", 1)
                if p.startswith(":") and p[1:].isdigit():
                    port = int(p[1:])
            out["protocol"] = protocol
            out["port"] = port or (443 if protocol == "https" else (80 if protocol == "http" else 0))
    elif re.match(r"^\[[0-9a-fA-F:]+\](?::\d+)?$", raw):
        raw_host, _, p = raw[1:].partition("]")
        if p.startswith(":") and p[1:].isdigit():
            port = int(p[1:])
    else:
        if ":" in raw and raw.count(":") == 1:
            raw_host, _, p = raw.rpartition(":")
            if p.isdigit():
                port = int(p)
            else:
                raw_host = raw
        else:
            raw_host = raw

    raw_host = raw_host.strip().lower().rstrip(".")
    if raw_host.startswith("[") and raw_host.endswith("]"):
        raw_host = raw_host[1:-1]
    try:
        ipaddress.ip_address(raw_host)
        out["ip"] = raw_host
    except ValueError:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw_host):
            out["ip"] = raw_host                      # IPv4 但 ipaddress 失败（越界等）也归 ip
        else:
            out["domain"] = _to_ascii_host(raw_host)  # Punycode
    out["host"] = raw_host
    if not out["port"]:
        out["port"] = port                      # URL 分支已补默认则不覆盖
    if not out["protocol"]:
        out["protocol"] = (protocol or "").lower()
    if not out["protocol"]:
        out["protocol"] = "https" if out["port"] == 443 else ("http" if out["port"] == 80 else "")
    return out


def dedup_key(asset: dict) -> str:
    """服务级去重 key：target|port|protocol，target 优先 domain→ip→host。"""
    target = asset.get("domain") or asset.get("ip") or asset.get("host") or ""
    return "|".join([str(target).lower(), str(asset.get("port") or 0),
                     str(asset.get("protocol") or "")])


def _clean_tags(tags) -> list:
    if not tags:
        return []
    seen, out = set(), []
    for t in tags:
        t = str(t).strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ============================================================================
# 快照
# ============================================================================

class AssetSnapshot:
    def __init__(self, path: str = ""):
        self.path = path or DEFAULT_SNAPSHOT
        self.data = {"_meta": {"version": 1, "updated_at": "", "count": 0},
                     "assets": {}}

    # ---- 加载/持久化 ----

    def load(self) -> "AssetSnapshot":
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, json.JSONDecodeError):
            self.data = {"_meta": {"version": 1, "updated_at": "", "count": 0},
                         "assets": {}}
        self.data.setdefault("assets", {})
        self.data.setdefault("_meta", {})
        return self

    def save(self) -> "AssetSnapshot":
        self.data["_meta"]["updated_at"] = _iso_now()
        self.data["_meta"]["count"] = len(self.data["assets"])
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)          # 原子写，防中断损坏
        return self

    # ---- upsert（借 UpsertAssets 语义） ----

    def upsert_asset(self, target: str, port: int = 0, protocol: str = "",
                     tags=None, source: str = "") -> dict:
        """按服务级 key upsert 一条资产：非空字段更新、first_seen 保留、last_seen 刷新、tags 并集。"""
        fields = split_target(target, port=port, protocol=protocol)
        key = dedup_key(fields)
        now = _iso_now()
        if not key or not fields.get("host") and not fields.get("ip") and not fields.get("domain"):
            return {}                             # 不可识别的目标，不建记录
        existing = self.data["assets"].get(key)
        if existing is None:
            existing = {
                "key": key,
                "target": fields.get("domain") or fields.get("ip") or fields.get("host"),
                "domain": fields.get("domain") or "",
                "ip": fields.get("ip") or "",
                "host": fields.get("host") or "",
                "port": fields["port"],
                "protocol": fields["protocol"] or "",
                "source": source or "manual",
                "tags": [],
                "first_seen": now,
                "last_seen": now,
                "risk_level": "unassessed",
                "findings": [],
                "vuln_count": 0,
                "pending_review": 0,
            }
            self.data["assets"][key] = existing
        else:
            # 非空覆盖 + tags 并集
            for f in ("domain", "ip", "host"):
                if fields.get(f):
                    existing[f] = fields[f]
            if fields["port"]:
                existing["port"] = fields["port"]
            if fields["protocol"]:
                existing["protocol"] = fields["protocol"]
            if not existing.get("target"):
                existing["target"] = fields.get("domain") or fields.get("ip") or fields.get("host")
            if source:
                existing["source"] = source
            existing["last_seen"] = now
        merged = _clean_tags(list(existing.get("tags") or []) + list(_clean_tags(tags)))
        existing["tags"] = merged[:30]
        return existing

    # ---- 写证据层结果 ----

    def record_verifications(self, results) -> dict:
        """写入 verify_findings 的 results：提取资产 + 记录 finding + 重算风险。"""
        created = 0
        updated = 0
        findings_new = 0
        for r in results or []:
            v = r.get("verdict") or {}
            assert_verdict = v.get("verdict")
            if assert_verdict not in ("confirmed", "refuted", "unverifiable"):
                continue
            matched = str(r.get("matched_at") or r.get("target") or "")
            target = str(r.get("target") or matched)
            fields = split_target(matched or target)
            if not target:
                target = fields.get("domain") or fields.get("ip") or fields.get("host") or ""
            is_new = dedup_key(fields) not in self.data["assets"]
            asset = self.upsert_asset(target, port=fields["port"], protocol=fields["protocol"],
                                      source=r.get("source_tool") or "verify")
            if not asset:
                continue
            if is_new:
                created += 1
            else:
                updated += 1
            finding_id = str(r.get("id") or r.get("matched_at") or "")
            at = _iso_now()
            rec = {
                "id": finding_id,
                "type": r.get("type", ""),
                "severity": str(r.get("severity") or "info").lower(),
                "verdict": assert_verdict,
                "evidence_sha256": v.get("evidence_sha256", ""),
                "repro_command": str(v.get("repro_command", ""))[:500],
                "matched_at": matched,
                "at": at,
            }
            found = next((f for f in asset["findings"] if f.get("id") == finding_id), None)
            if found:
                prior = found.get("verdict")
                found.update(rec)
                if prior != assert_verdict:        # 验证结果变化留痕
                    found["previous_verdict"] = prior
            else:
                asset["findings"].append(rec)
                findings_new += 1
            self._recompute_risk(asset)
        self.save()
        return {"assets_created": created, "assets_updated": updated,
                "findings_new": findings_new, "total_assets": len(self.data["assets"])}

    def _recompute_risk(self, asset: dict):
        """风险演算（借 Risk 动态计算）：confirmed 抬级别，refuted 留历史不计，unverifiable 计待复核。"""
        findings = asset.get("findings") or []
        open_sev = max((_SEV_RANK.get(f.get("severity"), 0)
                       for f in findings if f.get("verdict") == "confirmed"), default=0)
        pending = sum(1 for f in findings if f.get("verdict") == "unverifiable")
        asset["pending_review"] = pending
        asset["vuln_count"] = sum(1 for f in findings if f.get("verdict") == "confirmed")
        if open_sev > 0:
            asset["risk_level"] = {4: "critical", 3: "high", 2: "medium", 1: "low"}[open_sev]
        elif findings:
            asset["risk_level"] = "normal"
        else:
            asset["risk_level"] = "unassessed"

    # ---- 查询与报告 ----

    def query(self, q: str = "", risk_level: str = "", tags: str = "",
              limit: int = 50) -> list:
        q = (q or "").strip().lower()
        want_risk = (risk_level or "").strip().lower()
        want_tags = {t.strip().lower() for t in (tags or "").split(",") if t.strip()}
        out = []
        for a in self.data["assets"].values():
            if want_risk and a.get("risk_level") != want_risk:
                continue
            if want_tags and not want_tags.intersection(t.lower() for t in a.get("tags") or []):
                continue
            if q:
                hay = " ".join(str(a.get(k) or "") for k in
                               ("target", "domain", "ip", "host", "tags"))
                hay += f" {a.get('port', '')} {a.get('protocol', '')}"
                if q not in hay.lower():
                    continue
            out.append(a)
        out.sort(key=lambda a: _SEV_RANK.get(a.get("risk_level"), -1), reverse=True)
        return out[: max(1, int(limit))]

    def stats(self) -> dict:
        assets = self.data["assets"]
        by_risk = {}
        for a in assets.values():
            r = a.get("risk_level") or "unassessed"
            by_risk[r] = by_risk.get(r, 0) + 1
        return {"total_assets": len(assets),
                "total_confirmed": sum(a.get("vuln_count", 0) for a in assets.values()),
                "pending_review": sum(a.get("pending_review", 0) for a in assets.values()),
                "by_risk": by_risk,
                "path": self.path,
                "updated_at": self.data.get("_meta", {}).get("updated_at", "")}

    def to_markdown(self, overview_only: bool = False) -> str:
        st = self.stats()
        lines = ["# HexStrike 资产基线（跨任务记忆快照）", "",
                 f"- 快照：`{st['path']}` ｜ 更新时间：{st.get('updated_at') or '-'}",
                 f"- 资产数：{st['total_assets']} ｜ 当前确认漏洞：{st['total_confirmed']} ｜ 待复核：{st['pending_review']}",
                 "", "## 风险分布", "", "| 级别 | 数量 |", "|---|---|"]
        for r in ("critical", "high", "medium", "low", "normal", "unassessed"):
            lines.append(f"| {r} | {st['by_risk'].get(r, 0)} |")
        ranked = self.query(risk_level="")
        lines += ["", "## 资产明细", "",
                  "| target | port | protocol | 风险 | 漏洞数 | 待复核 | 首见 | 末见 | tags |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for a in ranked:
            lines.append(f"| {a.get('target', '')} | {a.get('port', '')} | {a.get('protocol', '')} "
                         f"| {a.get('risk_level', '')} | {a.get('vuln_count', 0)} "
                         f"| {a.get('pending_review', 0)} | {(a.get('first_seen') or '')[:10]} "
                         f"| {(a.get('last_seen') or '')[:10]} | {','.join(a.get('tags') or [])} |")
        if overview_only:
            return "\n".join(lines)
        lines += ["", "## Finding 详情（confirmed/待复核）"]
        for a in ranked:
            finds = [f for f in a.get("findings") or []
                     if f.get("verdict") in ("confirmed", "unverifiable")]
            if not finds:
                continue
            lines.append("")
            lines.append(f"### `{a.get('key', '')}`")
            for f in finds:
                cmd = (f.get("repro_command") or "").replace("\n", "<br>")
                lines.append(f"- **{f.get('type', '')}** {f.get('severity', '')} → {f.get('verdict', '')}  "
                             f"(sha256 `{(f.get('evidence_sha256') or '')[:12]}`) {f.get('at', '')[:10]}")
                if cmd:
                    lines.append(f"  `{cmd[:160]}`")
        return "\n".join(lines)


# ============================================================================
# 顶层函数（供 MCP 薄工具直接调用）
# ============================================================================

def snapshot_update(results_json, snapshot_path: str = "") -> dict:
    """把 verify_findings 结果（{results:[...]} 或数组）写入资产快照。"""
    try:
        if isinstance(results_json, (dict, list)):
            data = results_json
        else:
            data = json.loads(results_json)
    except (json.JSONDecodeError, TypeError):
        return {"error": "results_json 解析失败"}
    if isinstance(data, dict):
        results = data.get("results") or ([data] if data.get("verdict") else [])
    elif isinstance(data, list):
        results = data
    else:
        return {"error": "results_json 必须是数组或对象"}
    snap = AssetSnapshot(snapshot_path).load()
    return snap.record_verifications(results)


def query_assets(query: str = "", risk_level: str = "", tags: str = "",
                 limit: int = 50, snapshot_path: str = "") -> dict:
    snap = AssetSnapshot(snapshot_path).load()
    items = snap.query(query, risk_level, tags, limit)
    return {"total": len(items), "results": items, "stats": snap.stats()}


def snapshot_report(report_type: str = "overview", snapshot_path: str = "") -> dict:
    snap = AssetSnapshot(snapshot_path).load()
    overview_only = str(report_type).lower() != "full"
    return {"report": snap.to_markdown(overview_only=overview_only), "stats": snap.stats()}


if __name__ == "__main__":
    print("memory.py — 模块供 hexstrike_mcp.py 导入使用，无独立 CLI。", file=__import__("sys").stderr)