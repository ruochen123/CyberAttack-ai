#!/usr/bin/env python3
"""自然语言 → Web 控制台动作（改造④-NL）。

把用户指令解析为固定 action schema 并与 Web 控制台 API 对齐：
  {"op": "scan|verify|tag|delete|merge|report|stats", "params": {...}}
优先 LLM（DeepSeek chat；环境变量 DEEPSEEK_API_KEY），无 key/调用失败回退
本地关键词规则。动作含义扫描/验证会真实发请求，仅用于已授权目标。
"""

import json
import os
import re
import urllib.request

OPS = ("scan", "verify", "tag", "delete", "merge", "report", "stats")

SYSTEM = (
    "你是安全工具「HexStrike Web 控制台」的指令解析器。把用户的中文/英文指令"
    "转成 JSON，只输出 JSON，不要多余文字。schema：\n"
    '{"op":"scan|verify|tag|delete|merge|report|stats","params":{...}}\n'
    "op 说明：\n"
    "- scan：对目标发起渗透扫描并自动验证。params 含 target(必填，URL/域名/IP)、"
    "severity(如 critical,high)、tags(如 xss,sqli)、template、additional_args。\n"
    "- verify：独立验证 findings。params 含 findings_json(JSON 数组，每条含 "
    "target/type/matched_at/severity) 或 target(从资产快照取 foundings)。\n"
    "- tag/delete/merge：资产管理。params 含 target(或资产关键词) 与 add/keep。\n"
    "- report：导出 markdown 资产报告。params 空。\n"
    "- stats：资产统计。params 空。\n"
    '未知或缺失必要参数时 op 取最接近的，参数取空串，绝不编造 targets。\n'
    '输入示例："扫描 https://example.com:8443 的高危 xss" → '
    '{"op":"scan","params":{"target":"https://example.com:8443","severity":"high","tags":"xss","template":"","additional_args":""}}'
)

_URLISH = re.compile(r"(?:https?://)?[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[^\s\"',，。]*)?")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _extract_target(text: str) -> str:
    m = re.search(r"https?://\S+", text)
    if m:
        return m.group(0).rstrip(".,，。);:")
    m = _IPV4.search(text)
    if m:
        return m.group(0)
    # host:port 或 host
    for tok in re.split(r"\s+", text):
        tok = tok.strip("，。；;,()\"'")
        if tok.startswith(("http://", "https://")) or (("." in tok or tok.startswith(("10.", "192.168.", "172."))) and not any(x in tok for x in ("扫描", "验证", "标签", "删除", "合并", "报告", "资产", "高危", "低危"))):
            return tok
    return ""


def _extract_severity(text: str) -> str:
    m = re.search(r"(critical|high|medium|low|严重|高危|中危|低危)", text, re.I)
    if not m:
        return ""
    return {"critical": "critical", "严重": "critical", "high": "high", "高危": "high",
            "medium": "medium", "中危": "medium", "low": "low", "低危": "low"}[m.group(1).lower()]


def _extract_tags(text: str) -> str:
    hits = [t for t in ("xss", "sqli", "sql", "rce", "lfi", "rfi", "ssti", "cve",
                        "exposure", "tls", "port", "indirect-xss")
            if re.search(r"(?<![a-z0-9])" + t + r"(?![a-z0-9])", text, re.I)]
    return ",".join(dict.fromkeys(hits))


def _extract_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\[.*\]", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def _local_parse(text: str) -> dict:
    op = "stats"
    if "扫描" in text or re.search(r"\bscan\b", text, re.I):
        op = "scan"
    elif "验证" in text or "校验" in text or "复验" in text:
        op = "verify"
    elif "标签" in text or "标记" in text:
        op = "tag"
    elif "删除" in text or "移除" in text:
        op = "delete"
    elif "合并" in text:
        op = "merge"
    elif "报告" in text or "导出" in text:
        op = "report"
    elif "统计" in text or "状态" in text or "多少" in text or "资产" in text:
        op = "stats"

    params = {}
    if op in ("scan", "verify", "tag", "delete", "merge"):
        params["target"] = _extract_target(text)
    if op == "scan":
        params["severity"] = _extract_severity(text)
        params["tags"] = _extract_tags(text)
        params["template"] = ""
        params["additional_args"] = ""
    elif op == "verify":
        js = _extract_json(text)
        params["findings_json"] = json.dumps(js, ensure_ascii=False) if isinstance(js, list) else ""
    elif op == "tag":
        params["add"] = ""
        m = re.search(r"(?:给|把|为)?\s*(\S+)\s*(?:加|打|贴)?\s*(?:上)?标签|标签\s*[：:]?\s*([^\s，。]+)", text)
        if m:
            params["add"] = (m.group(2) or m.group(1) or "").strip("，。")
    elif op == "merge":
        params["keep"] = params.get("target", "")
    return {"op": op, "params": params}


def _llm_parse(text: str) -> dict:
    key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("DEEPSEEK_KEY") or ""
    if not key:
        return {}
    payload = {
        "model": "deepseek-chat",
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": text}],
        "temperature": 0,
        "max_tokens": 500,
    }
    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            content = json.loads(r.read().decode("utf-8"))
        action = json.loads(content["choices"][0]["message"]["content"])
    except Exception:
        return {}
    if action.get("op") in OPS and isinstance(action.get("params"), dict):
        return action
    return {}


def parse_action(text: str) -> dict:
    """返回 {op, params}。优先 LLM，失败回退本地规则。"""
    text = (text or "").strip()
    if not text:
        return {"op": "stats", "params": {}}
    action = _llm_parse(text)
    return action or _local_parse(text)


if __name__ == "__main__":
    import sys
    for t in sys.argv[1:] or ["扫描 https://example.com:8443 的高危 xss"]:
        print(repr(t), "→", parse_action(t))