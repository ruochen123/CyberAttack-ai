# HexStrike 证据验证层 — 设计文档

> 状态：**P0 + P1 已实施（2026-09-15），P2 待做** ｜ 定稿日期：2026-09-15
> 定位：HexStrike 改造清单第 ② 项，优先级最高（"可信渗透报告的分水岭"）
> 前置：改造 ① 补工具已完成（工具就绪 29/66 → 50/66）
> 实施：`verifiers.py`（契约 + VERIFIERS 注册表 + 5 验证器 + 批量/报告）+ `hexstrike_mcp.py` 新增 `verify_finding` / `verify_findings` 两个薄工具（已注册，152 工具）。本地全链路测试通过（confirmed/refuted/unverifiable 三态、软 404、closed 端口均正确）。三项待决已确认：五验证器全做、一并做 P1、仅授权目标。

## 1. 背景与问题

现有 HexStrike 的 151 个 `@mcp.tool` 全部只返回原始执行结果：

```python
{"stdout": ..., "stderr": ..., "return_code": ..., "success": ...,
 "timed_out": ..., "execution_time": ..., "timestamp": ...}
```

代码中**不存在 "finding" 这一层抽象**——`severity` 仅仅是传给扫描器的输入过滤参数，扫描器输出什么就往上抛什么。后果：

- **误报无法被机器推翻**：nuclei 报的 XSS、nmap 报的开放端口，全部以原始文本形式直接进入最终报告。
- **结论不可追溯**：报告里的每条结论，没有可独立重放的复现步骤。
- **可信度不可量化**：`health_check()`（hexstrike_mcp.py:560）已能量化"工具就绪度"，但没有任何东西量化"结论可信度"。

本设计新增一层：拿到 finding 后，用**与被验工具不同的机制**独立复现一次，产出可重放的证据与三态判定。

## 2. 设计原则

**核心约束：重跑同一个工具不算证据。** nuclei 报的 XSS 再用 nuclei 验，只是把同一份误报重复一遍，不产生任何新增信息。

1. **独立通道** — 不用产生该 finding 的工具去验证它（nuclei 报的用 curl 验，nmap 报的用裸 socket 验）
2. **最小复现** — 只发必要请求，1–3 次，**不改目标状态**（不写、不删、不爆破）
3. **三态判定** — `confirmed` / `refuted` / `unverifiable`（必须附原因）。**绝不把"没验出来"等同于"误报"**
4. **可复现** — 输出必须包含精确命令 + 原始响应片段 + 响应哈希，使人类可以手工重放

## 3. 数据契约

### Finding（输入）

```python
Finding = {
  "id":          "sha1(target|type|matched_at)",  # 确定性 ID：用于去重与复验定位
  "target":      "https://host",
  "type":        "xss|sqli|open_port|exposed_path|default_cred|tls_misconfig|cve|...",
  "source_tool": "nuclei|dalfox|nmap|ffuf|...",   # 用于挑选"独立"通道
  "matched_at":  "https://host/path?x=1",         # 具体命中点
  "severity":    "critical|high|medium|low|info",
  "raw":         "<原始输出片段，截断>",            # 保留可追溯性
}
```

### Verdict（输出）

```python
Verdict = {
  "verdict":         "confirmed|refuted|unverifiable",
  "repro_command":   "curl -sS 'https://...' | head -c 2000",  # 人类可重放
  "evidence":        "<原始响应片段>",
  "evidence_sha256": "...",     # 证据哈希：防篡改、可跨轮比对
  "detail":          "判定理由 / unverifiable 的原因",
  "latency_ms":      123,
}
```

## 4. 验证器注册表

`type → 验证函数` 的注册表。P0 实现以下 5 个，全部复用已安装工具（curl / nc / openssl），不引入新 binary：

| type | 独立复现方式 | 反误报关键点 |
|---|---|---|
| `open_port` | 裸 socket connect + banner 抓取（**不用 nmap**） | 区分 `filtered` 与 `closed`，避免把超时当开放 |
| `exposed_path` | 两次 GET：目标路径 + **随机路径**，比对状态码与 body 哈希 | **软 404 检测**——随机路径同样 200 则不判为暴露 |
| `xss` | 发送唯一标记串，检查响应体中是否**原样反射且未被 HTML 编码** | 同时验证反射点存在性与编码状态 |
| `sqli` | 布尔差分：`AND 1=1` 与 `AND 1=2` 各请求一次，比较响应长度 / 哈希 / 耗时 | 需要两次基线扰动，避免静态页面假阳性 |
| `tls_misconfig` | `openssl s_client` 取证书链与协商协议版本 | 直接读实际协商结果，不依赖扫描器结论 |

其余类型（`ssrf`、盲注 RCE、各类 OOB）**默认返回 `unverifiable` 并写明原因**（需要 callback 基础设施 / 需要凭据 / 具有破坏性），**不做假验证**。

## 5. 落地形态

```
~/hexstrike-ai/
├── verifiers.py          # 新增：契约 + VERIFIERS 注册表 + 5 个验证器实现
├── hexstrike_mcp.py      # 仅新增 2 个薄 @mcp.tool 包装
└── tools/*.json          # 不修改（验证器不是外部 binary 调用，无需 JSON 模板）
```

**不把实现堆进 `hexstrike_mcp.py`**（当前已 6399 行 / 255KB）。

在 `setup_mcp_server()`（hexstrike_mcp.py:1171 起）内新增：

```
verify_finding(finding_json: str, timeout: int = 30) -> Dict[str, Any]
    单条：解析 → 查 VERIFIERS[type] → 返回 Verdict

verify_findings(findings_json: str, max_concurrency: int = 4,
                only_types: str = "") -> Dict[str, Any]
    批量：返回逐条 Verdict + 汇总（confirmed / refuted / unverifiable 计数）
```

内部复用现成的 `hexstrike_client.execute_command()`——subprocess 执行、LRU 缓存、telemetry 全部复用，**不新写执行层**。

实际执行链（v7.0 已改为全本地）：
`hexstrike_client.execute_tool_async()` → `engine.submit_job()` → `build_tool_command()` → `execute_command()`，其中 `HexStrikeClient.safe_post()` 路由到 `self.engine.run_tool()`，无 HTTP。

## 6. 与现有能力的衔接

- **可信度量化**：`health_check()` 已量化工具就绪度；验证层在同一份输出上补"证据可信度"——报告中每条 finding 带 verdict 徽章，分 `已复现 / 未复现 / 无法验证` 三档，不再把扫描器原始输出直接当结论。这是最直接的接入点。
- **报告出口**：产出 markdown，天然可落飞书（复用 `lark-cli` 或 morning-briefing 那套推送链路）。
- **P2 一条龙**：nuclei **v3.8.0** 支持 `-jsonl` 输出，且 `-irr` 可将**实际请求/响应报文**嵌入 JSONL —— finding 自带原始报文作为证据，再叠一层独立复验即形成闭环。`tools/nuclei.json` 已有 `additional_args` 透传位，追加 `-jsonl` 无需改动模板。

## 7. 实施分期

| 阶段 | 内容 | 风险 |
|---|---|---|
| **P0** | ✅ 契约 + 5 个验证器 + `verify_finding`（单条） | 已完成（纯增量，未碰现有工具） |
| **P1** | ✅ `verify_findings` 批量 + markdown 报告生成（`report` 字段可直接落飞书） | 已完成 |
| **P2** | nuclei `-jsonl` 自动转 Finding → 自动验证，封装为 `nuclei_scan_and_verify` | 待做 |

**明确不做**：不重造 agent 循环（Claude Code 本身就是 agent）、不做分布式执行（现 `ThreadPoolExecutor` 够用）、不引入 Neo4j / 图数据库（PentAGI 已评估，代价不划算）。

## 8. 边界与已知局限

- 需要对目标**真发请求**，仅限已授权目标使用（设计上按最小复现，但不改目标状态）。
- 破坏性类型（RCE、文件写入等）**默认不自动验证**，仅标记 `unverifiable`。
- 认证后的漏洞需要调用方传入凭据。
- OOB 类（SSRF、盲注 RCE）需要 callback 基础设施（DNS/HTTP 回连监听），本期**不自动验证**。

## 9. 待决事项（2026-09-15 已确认）

1. **P0 范围**：✅ 按本文 5 个验证器全做（open_port / exposed_path / xss / sqli / tls_misconfig）。
2. **报告出口**：✅ 一并做 P1——`verify_findings` 批量 + markdown 报告（`report` 字段，可后续接飞书）。
3. **授权确认**：✅ 已确认仅对授权目标使用（验证器按最小复现实现，1–3 次请求，不改目标状态）。
