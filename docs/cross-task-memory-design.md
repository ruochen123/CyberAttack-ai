# HexStrike 轻量跨任务记忆（改造③）— 设计文档

> 状态：**P0 已实施（2026-09-15）** ｜ 借鉴来源：CyberStrikeAI 资产记忆/结果治理（参考仓库 `~/references/CyberStrikeAI`，已 clone）
> 定位：改造清单第 ③ 项。补 HexStrike 最缺的"跨任务记忆"，吸收资产规范化/去重/合并/风险演算，**不引 Neo4j/SQLite**（沿用 [[project_pentagi-evaluation]] 结论）。
> 交付：`memory.py`（AssetSnapshot：normalize / dedup_key / upsert / 验证驱动风险 / 查询 / markdown 报告）+ `hexstrike_mcp.py` 新增 `snapshot_update` / `query_assets` / `snapshot_report` 三个薄工具（156 工具注册）。单元测试 + 集成冒烟通过。

## 1. 要解决的问题

- 每次渗透会话的记忆都丢在会话里：扫过的目标、确认的资产、哪些已复验、风险集中在哪，无法跨任务复用。
- CyberStrikeAI（资产清单 inventory + 跨会话攻击链）是实物版答案，但 SQLite/RBAC/WebUI/LLM 建链太重在 HexStrike 不适配。
- 对照结论：只偷「资产规范化 + 服务级去重 key + upsert 合并 + 风险演算」四样，其余（独立通道复验、异步执行）我们已有或更强。

## 2. 设计原则

1. **单 JSON 文件快照**：人可读、可审计、可落飞书、可 diff。不引 DB。
2. **服务级去重**：`target|port|protocol` 作 key（target 优先 domain → IP → host）。
3. **upsert 语义**：重复记录不新建——非空字段更新、`last_seen` 刷新、`first_seen` 保留、tags 求并集。
4. **验证驱动风险**：`confirmed` 抬风险、`refuted` 留历史不计当前风险、`unverifiable` 待复核。与证据层三态强绑定。
5. **确定性建链**：资产→finding→证据（命令+哈希）用代码连边，不依赖 LLM。

## 3. 数据契约（JSON 快照）

```python
Snapshot = {
  "_meta": {"version": 1, "updated_at": "...", "count": N},
  "assets": {
    "<dedup_key>": {
      "key":        "example.com|443|https",
      "target":     "example.com",            # 优先 domain → IP → host（lowercase）
      "domain": "", "ip": "", "host": "",
      "port": 443, "protocol": "https",
      "source":     "nuclei|manual|...",
      "tags":       ["auth_bound", "prod"],
      "first_seen": "2026-09-15T...",          # 首次出现，upsert 保留
      "last_seen":  "2026-09-15T...",          # 每次 upsert 刷新
      "risk_level": "critical|high|medium|low|normal|unassessed",
      "findings": [                            # 历史 finding 记录（含已 refuted，供追溯）
        {
          "id": "sha1(target|type|matched_at)",
          "type": "xss|sqli|open_port|...",
          "severity": "high",
          "verdict": "confirmed|refuted|unverifiable",
          "evidence_sha256": "...",
          "repro_command": "curl ...",
          "matched_at": "https://host/path?x=1",
          "at": "2026-09-15T..."
        }
      ],
      "vuln_count": 2                          # 当前 open(confirmed) 计数
    }
  }
}
```

## 4. 与证据层的衔接

`verify_findings` 之后结果可写入快照：调用方把 Findings+Verds 喂 `snapshot.record_verifications(client, results)` 或 MCP `snapshot_update`。

- riske 计算：按 severity 加权 open 数决定 `risk_level`：critical>0→critical；high>0→high；medium>0→medium；low>0→low；有扫无 open→normal；无记录→unassessed。refuted 不参与；unverifiable 计入"待复核"标记但不抬等级。

## 5. 落地形态

```
~/hexstrike-ai/
├── memory.py                  # 新增：AssetSnapshot（normalize/dedup_key/upsert/风险/查询/报告）
├── hexstrike_mcp.py           # 新增 3 个薄 @mcp.tool
├── ai-security-snapshot.json  # 快照默认落盘位置（.gitignore 或留库内自定）
└── docs/cross-task-memory-design.md  # 本文档
```

MCP 工具（复用 `HexStrikeClient`，不新增执行层）：

- `snapshot_update(findings_json: str, snapshot_path: str = "")` — 传入 verify_findings 结果（数组/{results}）→ upsert 资产 + 记录 verdict → 返回快照计数
- `query_assets(query: str = "", risk_level: str = "", tags: str = "", limit: int = 50)` — 查资产基线
- `snapshot_report(report_type: str = "overview")` — markdown 资产基线/风险汇总（可落飞书）

## 6. 分期

- **P0**：`memory.py`（normalize/dedup/upsert/risk/查询/报告）+ 3 个 MCP 工具 + 本地测试，纯增量。
- **P1**（可选续）：「扫描补资产」自动入库（扫完 `nuclei_scan_and_verify` 自动 upsert）+ 结果治理落盘引用。

## 7. 明确不做

- 不引 SQLite/Neo4j/向量；不做 RBAC/WebUI；不用 LLM 建攻击链（模型是确定性的）；不做分布式。