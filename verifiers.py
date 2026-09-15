#!/usr/bin/env python3
"""HexStrike 证据验证层 — Finding/Verdict 契约 + 独立通道验证器 + 批量与 markdown 报告。

设计见 docs/evidence-layer-design.md（改造②）。核心约束：重跑同一个工具不算证据，
验证器用与被验工具不同的机制（curl/nc/openssl）独立复现 finding，产出可重放的证据
与三态判定（confirmed / refuted / unverifiable），绝不把"没验出来"当"误报"。

对外只暴露两个函数，由 hexstrike_mcp.py 的薄 @mcp.tool 包装调用：
    verify_finding(client, finding_json, timeout=30)
    verify_findings(client, findings_json, max_concurrency=4, only_types="")
执行统一走 client.execute_command(command, use_cache=False)，不新写执行层。
"""

import hashlib
import json
import random
import re
import string
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

VERDICTS = {"confirmed", "refuted", "unverifiable"}
EVIDENCE_MAX = 4000
RESPONSE_MAX = 8000
_OK_CODES = {"200", "201", "202", "204", "301", "302", "303", "307", "308"}


# ============================================================================
# 工具性辅助
# ============================================================================

def finding_id(target: str, ftype: str, matched_at: str) -> str:
    return hashlib.sha1(f"{target}|{ftype}|{matched_at}".encode("utf-8", "ignore")).hexdigest()


def _sha256(text) -> str:
    if text is None:
        text = ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def _run(client, command: str, timeout: int) -> dict:
    """统一执行入口：复用 hexstrike_client.execute_command，禁用缓存（验证必须真实请求）。"""
    start = time.time()
    result = client.execute_command(command, use_cache=False)
    latency_ms = int((time.time() - start) * 1000)
    return result, latency_ms


def _verdict(verdict: str, repro_command: str, evidence: str, detail: str,
             latency_ms: int) -> dict:
    if verdict not in VERDICTS:
        verdict = "unverifiable"
    evidence = (evidence or "")[:EVIDENCE_MAX]
    return {
        "verdict": verdict,
        "repro_command": repro_command,
        "evidence": evidence,
        "evidence_sha256": _sha256(evidence),
        "detail": detail,
        "latency_ms": latency_ms,
    }


def _parse_endpoint(finding: dict, default_port: int = 443):
    """解析 host:port 与 URL 基址。返回 (scheme|None, host, port, url_base|None)。

    matched_at 优先（含端口/具体路径），fallback 到 target。url_base 去掉 query/fragment。
    """
    matched = (finding.get("matched_at") or "").strip()
    target = (finding.get("target") or "").strip()
    raw = matched or target
    if raw.startswith(("http://", "https://")):
        base = re.split(r"[?#]", raw, maxsplit=1)[0]
        try:
            pu = urllib.parse.urlparse(base)
        except ValueError:
            return None, None, None, None
        if not pu.hostname:
            return None, None, None, None
        scheme = pu.scheme
        host = pu.hostname
        port = pu.port or (443 if scheme == "https" else 80)
        return scheme, host, port, base
    m = re.match(r"^(?:\[)?([^\[\]:]+)(?:\])?:(\d+)$", raw)
    if m:
        return None, m.group(1), int(m.group(2)), None
    m2 = re.match(r"^(?:\[)?([^\[\]:]+)(?:\])?:(\d+)$", target)
    if m2:
        return None, m2.group(1), int(m2.group(2)), None
    return None, raw, default_port, None


def _http_fetch(client, url: str, timeout: int):
    """对 URL 发一次 GET，返回 (code, body, cmd, latency_ms, stderr)。"""

    cmd = f"curl -sS -L --max-time {timeout} --compressed -w '\\n%{{http_code}}' '{url}'"
    result, latency = _run(client, cmd, timeout)
    stdout = result.get("stdout") or ""
    parts = stdout.rsplit("\n", 1)
    code = parts[-1].strip() if len(parts) > 1 else ""
    body = parts[0] if len(parts) > 1 else stdout
    if not code.isdigit():
        code = ""
        body = stdout
    return code, body, cmd, latency, (result.get("stderr") or "")


# ============================================================================
# 五个验证器（独立通道，不用产生该 finding 的工具）
# ============================================================================

# --- open_port：裸 socket connect（不用 nmap） ---

def _verify_open_port(client, finding, timeout) -> dict:
    _scheme, host, port, _base = _parse_endpoint(finding, default_port=443)
    if not host or not port:
        return _verdict("unverifiable", "", "", "无法从 finding 提取 host:port（target/matched_at 为空）", 0)
    cmd = f"nc -vz -w {timeout} {host} {port}"
    result, latency = _run(client, cmd, timeout)
    out = result.get("stdout") or ""
    err = result.get("stderr") or ""
    evidence = (out + err).strip()
    if result.get("return_code") == 0:
        return _verdict("confirmed", cmd, evidence, "裸 socket connect 成功，端口开放", latency)
    blob = (out + err).lower()
    if "refused" in blob or "61" in err:
        return _verdict("refuted", cmd, evidence, "TCP 连接被拒绝（closed），端口未开放", latency)
    if result.get("timed_out") or "timed out" in blob or "timeout" in blob:
        return _verdict("unverifiable", cmd, evidence,
                        "连接超时/无响应：filtered 或被防火墙丢弃，无法区分 open/closed", latency)
    if "name or service not known" in blob or "sockaddr failed" in blob:
        return _verdict("unverifiable", cmd, evidence, "DNS 解析失败，无法验证", latency)
    return _verdict("unverifiable", cmd, evidence,
                    f"连接未成功且非明确拒绝：{evidence[:300] or '无输出'}", latency)


# --- exposed_path：目标路径 vs 随机路径（各 1 次 GET），软 404 检测 ---

def _verify_exposed_path(client, finding, timeout) -> dict:
    _scheme, _host, _port, base = _parse_endpoint(finding, default_port=443)
    if not base:
        return _verdict("unverifiable", "", "", "无法从 finding 提取 http(s) URL（matched_at）", 0)
    token = "HXV" + "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    rand_path = re.sub(r"/+$", "", base) + f"/{token}.html"
    t_code, t_body, t_cmd, t_lat, t_err = _http_fetch(client, base, timeout)
    r_code, r_body, r_cmd, r_lat, r_err = _http_fetch(client, rand_path, timeout)
    cmd = f"{t_cmd}\n{r_cmd}"
    evidence = (f"target={base} -> {t_code or '(失败)'} sha256={_sha256(t_body)[:12]}\n"
                f"random={rand_path} -> {r_code or '(失败)'} sha256={_sha256(r_body)[:12]}")
    if not t_code or not r_code:
        detail = (t_err or r_err or "curl 请求失败（网络/DNS/超时）")[:300]
        return _verdict("unverifiable", cmd, evidence, f"无法同时取到两个状态码：{detail}", t_lat + r_lat)
    if t_code == r_code:
        t_hash, r_hash = _sha256(t_body), _sha256(r_body)
        if t_hash == r_hash:
            return _verdict("refuted", cmd, evidence,
                            f"软 {t_code}：随机路径返回相同状态码与相同 body 哈希，目标路径未被特殊暴露",
                            t_lat + r_lat)
        if int(t_code) >= 400:
            return _verdict("refuted", cmd, evidence,
                            f"目标与随机路径同为 {t_code} 但 body 不同，属服务级拒绝而非路径暴露",
                            t_lat + r_lat)
        return _verdict("confirmed", cmd, evidence,
                        f"目标与随机路径均 {t_code} 但 body 不同，目标路径返回独立内容",
                        t_lat + r_lat)
    if t_code in _OK_CODES:
        return _verdict("confirmed", cmd, evidence,
                        f"目标路径可达（{t_code}）而随机路径 {r_code}，非软 404",
                        t_lat + r_lat)
    return _verdict("unverifiable", cmd, evidence,
                    f"目标 {t_code} / 随机 {r_code} 组合不明确，需人工判断", t_lat + r_lat)


# --- xss：唯一标记串反射 + 编码状态 ---

def _verify_xss(client, finding, timeout) -> dict:
    matched = (finding.get("matched_at") or "").strip()
    if not matched.startswith(("http://", "https://")):
        return _verdict("unverifiable", "", "", "matched_at 非 http(s) URL，无法构造反射测试", 0)
    pu = urllib.parse.urlparse(matched)
    if not pu.query:
        return _verdict("unverifiable", "", "",
                        "matched_at 无 query 参数（POST 类 / 需凭据场景默认不验证）", 0)
    token = "HXV" + "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    payload = f"<b>{token}</b>"
    qs = urllib.parse.parse_qsl(pu.query, keep_blank_values=True)
    key = qs[0][0]
    new_qs = [(kv[0], payload if kv[0] == key else kv[1]) for kv in qs]
    url = urllib.parse.urlunparse((pu.scheme, pu.netloc, pu.path, pu.params,
                                   urllib.parse.urlencode(new_qs), pu.fragment))
    code, body, cmd, latency, err = _http_fetch(client, url, timeout)
    if not body and not code:
        return _verdict("unverifiable", cmd, "", f"请求失败：{(err or 'curl 无输出')[:300]}", latency)
    decoded = body.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    if payload in body:
        return _verdict("confirmed", cmd, body,
                        f"标识串 {payload} 原样反射且未被 HTML 编码，参数值未过滤", latency)
    if token in body or token in decoded:
        if payload in decoded and payload not in body:
            return _verdict("refuted", cmd, body,
                            f"标识串被 HTML 编码后反射（&lt;/&gt;），无法原样注入脚本", latency)
        return _verdict("refuted", cmd, body,
                        f"仅 token 字符串被反射，<b> 标签缺失：参数值被过滤/剥离，XSS 前提不成立", latency)
    return _verdict("refuted", cmd, body, "标识串未出现在响应体中，无反射点", latency)


# --- sqli：布尔差分 AND 1=1 vs AND 1=2（各 1 次 GET） ---

def _verify_sqli(client, finding, timeout) -> dict:
    matched = (finding.get("matched_at") or "").strip()
    if not matched.startswith(("http://", "https://")):
        return _verdict("unverifiable", "", "", "matched_at 非 http(s) URL，无法构造差分请求", 0)
    pu = urllib.parse.urlparse(matched)
    if not pu.query:
        return _verdict("unverifiable", "", "",
                        "matched_at 无 query 参数（时间型盲注 / 需要 callback 的场景默认不验证）", 0)
    qs = urllib.parse.parse_qsl(pu.query, keep_blank_values=True)
    key, val = qs[0]

    def _url(cond):
        new_qs = [(kv[0], (val + cond) if kv[0] == key else kv[1]) for kv in qs]
        return urllib.parse.urlunparse((pu.scheme, pu.netloc, pu.path, pu.params,
                                        urllib.parse.urlencode(new_qs), pu.fragment))

    c1_code, b1, c1_cmd, c1_lat, c1_err = _http_fetch(client, _url("' AND '1'='1"), timeout)
    c2_code, b2, c2_cmd, c2_lat, c2_err = _http_fetch(client, _url("' AND '1'='2"), timeout)
    cmd = f"{c1_cmd}\n{c2_cmd}"
    evidence = (f"AND '1'='1 -> HTTP {c1_code or '(失败)'} len={len(b1)} sha256={_sha256(b1)[:12]}\n"
                f"AND '1'='2 -> HTTP {c2_code or '(失败)'} len={len(b2)} sha256={_sha256(b2)[:12]}")
    if (not c1_code and not b1) or (not c2_code and not b2):
        return _verdict("unverifiable", cmd, evidence,
                        f"差分请求失败：{(c1_err or c2_err or 'curl 无输出')[:300]}", c1_lat + c2_lat)
    if _sha256(b1) != _sha256(b2):
        detail = f"布尔差分成立：两类条件返回不同响应（len {len(b1)} vs {len(b2)}）"
        if len(b1) == len(b2):
            detail += "（长度相同但内容不同，存在藏匿型差异）"
        return _verdict("confirmed", cmd, evidence, detail, c1_lat + c2_lat)
    return _verdict("refuted", cmd, evidence,
                    "两种条件返回完全相同响应，无布尔差分（静态页或无法注入）", c1_lat + c2_lat)


# --- tls_misconfig：openssl s_client 直接读实际协商结果 ---

_WEAK_PROTO = re.compile(r"(ssl[23]|tlsv1\.0|tls1\.0|sslv3|tlsv1(?=[^.]|$))", re.I)


def _verify_tls_misconfig(client, finding, timeout) -> dict:
    _scheme, host, port, _base = _parse_endpoint(finding, default_port=443)
    if not host or not port:
        return _verdict("unverifiable", "", "", "无法从 finding 提取 host:port", 0)
    brief_cmd = f"openssl s_client -connect {host}:{port} -servername {host} -brief 2>&1 | head -c 2000"
    cert_cmd = (f"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>/dev/null "
                f"| openssl x509 -noout -subject -issuer -dates 2>/dev/null")
    b, b_lat = _run(client, brief_cmd, timeout)
    c, c_lat = _run(client, cert_cmd, timeout)
    brief = (b.get("stdout") or "").strip()
    cert = (c.get("stdout") or "").strip()
    evidence = (brief + "\n--- cert ---\n" + cert).strip()[:EVIDENCE_MAX]
    cmd = f"{brief_cmd}\n{cert_cmd}"
    total_lat = b_lat + c_lat

    proto_m = re.search(r"Protocol version[:\s]*([\w.\-]+)", brief)
    if not proto_m:
        low = brief.lower()
        if not low:
            return _verdict("unverifiable", cmd, "", "openssl 无输出，无法验证", total_lat)
        if "connection refused" in low:
            return _verdict("refuted", cmd, evidence, "TLS 连接被拒绝，端口未监听", total_lat)
        if "errno=61" in low:
            return _verdict("refuted", cmd, evidence, "TLS 连接被拒绝（errno=61, ECONNREFUSED），端口未监听", total_lat)
        if any(k in low for k in ("timed out", "timeout", "errno=60", "unable to connect",
                                  "no route", "name or service not known", "sockaddr")):
            return _verdict("unverifiable", cmd, evidence,
                            "TLS 连接超时/不可达/DNS 失败，无法读取协商结果", total_lat)
        if any(k in low for k in ("no protocol", "wrong version", "handshake failure",
                                  "ssl error", "alert")):
            return _verdict("unverifiable", cmd, evidence,
                            f"TLS 握手失败（{low[:160]}），非纯 TLS 端口或版本不兼容", total_lat)
        return _verdict("unverifiable", cmd, evidence,
                        f"TLS 连接未建立：{low[:200]}", total_lat)

    actual_proto = proto_m.group(1).strip()
    cipher_m = re.search(r"Cipher is[:\s]*([^\n]+)", brief)
    actual_cipher = (cipher_m.group(1).strip() if cipher_m else "")

    raw = (finding.get("raw") or "")
    weak = _WEAK_PROTO.search(raw)
    if weak:
        claimed = weak.group(0).upper()
        if "tlsv1" in actual_proto.lower() or "ssl" in actual_proto.lower():
            return _verdict("confirmed", cmd, evidence,
                            f"raw 断言弱协议 {claimed}，实测协商到 {actual_proto}（{actual_cipher}）", total_lat)
        return _verdict("refuted", cmd, evidence,
                        f"raw 断言弱协议 {claimed}，但实测协商到 {actual_proto}（{actual_cipher}）", total_lat)
    if re.search(r"expired|过期|notAfter", raw, re.I):
        not_after = re.search(r"notAfter\s*=\s*(\S+)", cert)
        if not_after:
            from datetime import datetime
            try:
                expiry = datetime.strptime(not_after.group(1), "%b %d %H:%M:%S %Y %Z")
                if expiry < datetime.utcnow():
                    return _verdict("confirmed", cmd, evidence,
                                    f"证书已过期（notAfter={not_after.group(1)}）", total_lat)
                return _verdict("refuted", cmd, evidence,
                                f"证书未过期（notAfter={not_after.group(1)}）", total_lat)
            except ValueError:
                pass
    if re.search(r"self[- ]signed|自签名", raw, re.I):
        subj = re.search(r"subject\s*=\s*(.*)", cert)
        iss = re.search(r"issuer\s*=\s*(.*)", cert)
        if subj and iss:
            if subj.group(1).strip() == iss.group(1).strip():
                return _verdict("confirmed", cmd, evidence, "自签名证书（subject == issuer）", total_lat)
            return _verdict("refuted", cmd, evidence, "证书由 CA 签发（subject != issuer），非自签名", total_lat)
    return _verdict("unverifiable", cmd, evidence,
                    f"raw 未断言具体 misconfig；实测协商 {actual_proto}（{actual_cipher}）。"
                    f"如需确认请补充 raw 断言（弱协议/过期/自签名关键词）", total_lat)


# ============================================================================
# 验证器注册表
# ============================================================================

VERIFIERS = {
    "open_port": _verify_open_port,
    "exposed_path": _verify_exposed_path,
    "xss": _verify_xss,
    "sqli": _verify_sqli,
    "tls_misconfig": _verify_tls_misconfig,
}

_DEFAULT_UNSUPPORTED = {
    "ssrf": "需要 OOB/DNS 回连 callback 基础设施，本期不做",
    "rce": "破坏性验证，默认不自动执行",
    "file_write": "破坏性验证，默认不自动执行",
    "cve": "需对应版本指纹与打点，扫描器结论不足以独立复现",
    "default_cred": "需要有效凭据，最小复现原则不自动尝试登录",
}


def verify_finding(client, finding_json, timeout: int = 30, _input_parsed: bool = False) -> dict:
    """单条验证：解析 finding → 查 VERIFIERS[type] → 返回含 Verdict 的完整结果。"""
    finding = finding_json if _input_parsed else None
    if not _input_parsed:
        try:
            finding = json.loads(finding_json)
        except (json.JSONDecodeError, TypeError) as e:
            return {"error": f"finding_json 解析失败: {e}", "verdict": None}
    if not isinstance(finding, dict):
        return {"error": "finding 必须是对象", "verdict": None}

    ftype = str(finding.get("type") or "").strip().lower()
    target = str(finding.get("target") or "")
    matched_at = str(finding.get("matched_at") or "")
    fid = str(finding.get("id") or finding_id(target, ftype, matched_at))

    base = {"id": fid, "type": ftype, "target": target, "matched_at": matched_at,
            "source_tool": finding.get("source_tool", ""),
            "severity": finding.get("severity", "info")}

    if ftype not in VERIFIERS:
        reason = _DEFAULT_UNSUPPORTED.get(ftype, "不在验证器注册表中")
        base["verdict"] = _verdict("unverifiable", "", "", f"未注册类型：{reason}（不做假验证）", 0)
        return base

    try:
        base["verdict"] = VERIFIERS[ftype](client, finding, max(1, int(timeout)))
    except Exception as e:
        base["verdict"] = _verdict("unverifiable", "", "", f"验证器异常：{e}", 0)
        base["error"] = str(e)
    return base


def _coerce_findings(raw):
    """接受 JSON 数组 / {findings:[...]} / {单个 finding} / JSONL 多行，归一到 list[dict]。"""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return raw["findings"] if isinstance(raw.get("findings"), list) else [raw]
    text = (raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data["findings"] if isinstance(data.get("findings"), list) else [data]
    docs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            docs.extend(obj)
        elif isinstance(obj, dict):
            docs.append(obj)
    return docs


def render_markdown_report(results: list) -> str:
    counts = {k: 0 for k in VERDICTS}
    for r in results:
        v = r.get("verdict")
        if isinstance(v, dict):
            counts[v.get("verdict", "unverifiable")] = counts.get(v.get("verdict", "unverifiable"), 0) + 1
    badge = {"confirmed": "✅ 已复现", "refuted": "❌ 未复现", "unverifiable": "⚠️ 无法验证"}
    lines = ["# HexStrike Finding 验证报告", "",
             f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"- 验证条数：{len(results)}", "",
             "| 判定 | 数量 |", "|---|---|"]
    for k in ("confirmed", "refuted", "unverifiable"):
        lines.append(f"| {badge.get(k, k)} | {counts[k]} |")
    lines += ["", "## 明细", "",
              "| ID | 类型 | 目标 | 严重度 | 判定 | 复现命令 |", "|---|---|---|---|---|---|"]
    for r in results:
        v = r.get("verdict") or {}
        rid = (r.get("id") or "")[:8]
        cmd = (v.get("repro_command") or "").replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {rid} | {r.get('type', '')} | {r.get('target', '')} | "
                     f"{r.get('severity', 'info')} | {badge.get(v.get('verdict'), '⚠️')} | `{cmd[:120]}` |")
    lines += ["", "## 详情"]
    for r in results:
        v = r.get("verdict") or {}
        lines.append("")
        lines.append(f"### `{(r.get('id') or '')[:12]}` [{r.get('type', '')}] {v.get('verdict', '')}")
        lines.append(f"- target: `{r.get('target', '')}`")
        lines.append(f"- matched_at: `{r.get('matched_at', '')}`")
        lines.append(f"- source_tool: `{r.get('source_tool', '')}` | severity: {r.get('severity', 'info')}")
        lines.append(f"- **判定**：{v.get('detail', '')}")
        if v.get("repro_command"):
            lines.append("- **复现命令**：")
            for c in str(v["repro_command"]).split("\n"):
                lines.append(f"  ```bash\n{c}\n  ```")
        if v.get("evidence"):
            ev = str(v["evidence"])
            lines.append(f"- **证据**（sha256 `{v.get('evidence_sha256', '')[:12]}`）：")
            lines.append("  ```")
            lines.extend("  " + ln for ln in ev.split("\n"))
            lines.append("  ```")
    return "\n".join(lines)


def verify_findings(client, findings_json: str, max_concurrency: int = 4,
                    only_types: str = "") -> dict:
    """批量验证：并发逐条验证，返回 Verdict 列表 + 汇总计数 + markdown 报告。"""
    try:
        findings = _coerce_findings(findings_json)
    except json.JSONDecodeError as e:
        return {"error": f"findings_json 解析失败: {e}"}

    whitelist = {t.strip().lower() for t in only_types.split(",") if t.strip()}
    if whitelist:
        findings = [f for f in findings
                    if str(f.get("type") or "").strip().lower() in whitelist]

    empty = {"total": 0, "confirmed": 0, "refuted": 0, "unverifiable": 0,
             "results": [], "report": render_markdown_report([])}
    if not findings:
        empty["total"] = 0
        return empty

    results = []
    workers = max(1, min(int(max_concurrency), len(findings)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(verify_finding, client, f, _input_parsed=True) for f in findings]
        for f in futs:
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"error": str(e), "verdict": None})

    counts = {k: 0 for k in VERDICTS}
    for r in results:
        v = r.get("verdict")
        if isinstance(v, dict):
            key = v.get("verdict")
            counts[key] = counts.get(key, 0) + 1
    return {
        "total": len(results),
        "confirmed": counts["confirmed"],
        "refuted": counts["refuted"],
        "unverifiable": counts["unverifiable"],
        "results": results,
        "report": render_markdown_report(results),
    }


if __name__ == "__main__":
    import sys
    print("verifiers.py — 模块供 hexstrike_mcp.py 导入使用，无独立 CLI。", file=sys.stderr)