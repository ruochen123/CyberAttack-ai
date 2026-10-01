# HexStrike Web 控制台 — 使用说明

> 只监听 **127.0.0.1**（本机）。扫描 / 验证 / 手动工具都会对目标**真实发请求**。
> 心智模型一行：**每发起一次＝一个任务，全部以任务形式并行跑，各自一张卡**。

## 启动

```bash
hexdash             # 起 :8765 独立进程，已在运行则复用；日志 /tmp/hexdash.log
hexdash stop        # 停止
```

等价：`cd ~/hexstrike-ai && ./hexstrike-env/bin/python3 dashboard.py`。也可在 Claude 会话内经 MCP 工具 `start_dashboard` / `stop_dashboard` 启停（同一形态）。打开 http://127.0.0.1:8765/。

## 面板（左右两栏）

- **左 `col-tools`**：使用说明 · 起手·自主任务（主线）· 手动工具（默认收起，`mTgl` 展开）
- **右 `col-results`**：任务卡池 · 系统事件 · 资产快照（sticky，独立滚动）

窄屏（<900px）自动回落单栏。

## 主线：自主任务（起手）

- 输入框＝整段 `claude -p` 命令行：`/技能名`→SKILL.md 注入；`--model`/`--max-turns`/`--allowedTools` 原样透传；其余为 prompt。
- 输入 `/` 弹分组菜单（`/api/menu`）：`/skills` `/mcp`（服务器）`/tools`（192 个 hexstrike 工具）`/plugin` `/cmd`。
- 选项：模型下拉（--model）；**工具白名单**（花名册注入 --allowedTools）；**🗂 隔离上下文**（默认开）；**续上一会话**（复用最近一次 agent 会话，可无限续）。
- **多轮交互**：运行中卡上 ⏸ 中断（会话保留）→ 在**这张卡**的输入框写调整 → ▶ 继续（`--resume` 同一会话带记忆续跑），可反复中断/续跑。
- **隔离上下文（默认开）**：agent 工作目录用 `.agent/<会话id>`，项目级 auto-memory 按任务隔离，**并行任务互不污染记忆**；user 级 auto-memory 始终共享；续跑复用同一目录读回原记忆。取消勾选＝共享项目级记忆（同一攻防场景协作时用）。

## 并行池与任务卡池

- 并行上限 **3**（env `HEXSTRIKE_CONCURRENCY` 可改）；满池时新任务返回 409「并行池已满」。
- **每种任务一张卡**：卡头＝类型/状态/耗时；卡内＝该任务自己的日志；卡尾「✔ 结论」＝执行摘要；⏸/▶/✖ 只作用于该卡。
- `GET /api/jobs` 列全部任务；任务类型 kind：`scan`/`verify`/`agent`/`chain`/`util`，显示名走 `KIND` 映射。

## 手动工具（job kind `chain`/`util`，全部进卡池，按阶段分组）

| 阶段 | 工具 | 说明 |
|---|---|---|
| 侦察·EXP | 关联 EXP | whatweb 指纹 → 组件/版本 + searchsploit/nuclei tag/msf 模块清单 |
| 漏洞 | 扫描/验证 | 指定 tags/severity 的 nuclei → 自动独立复验；或对 findings JSON 独立验证 |
| 漏洞 | 弱口令喷洒 | 定向 POST 弱口令（限速、429/403/401 自动停；成功判定启发式，命中需按站点调 fail_indicator） |
| 漏洞 | OAST 盲测 | interactsh 拿回显域名→嵌进 SSRF/XXE/XSS payload→轮询回显坐实 |
| 利用 | 反连+监听 | 一行 payload（bash/nc/python/perl/openssl/powershell…）+ 本地监听（nc 或容器 msf handler） |
| 利用 | 未授权服务 | redis / ldap / mongo 容器内检查（匿名可达即未授权） |
| 逻辑 | IDOR 越权 | URL 含 `{id}` 做 高/低权/匿名 三视角差分 |
| 取证 | JS 密钥 | 扫前端 JS 硬编码密钥/API key |
| 取证 | 截图 | headless Chrome 全页 PNG（落 ~/hexstrike-ai/screenshots） |

手动工具是「精确档位」：普通流程交给自主任务；想精确做某一步 / 单点坐实 / 取证时再展开使用。

## 系统事件 与 资产快照

- **系统事件** = 平台消息（提交 / 完成汇总 / 错误），明确**不含**任务日志（各任务日志在它们自己的卡片里）。
- **资产快照**（`ai-security-snapshot.json`，已 .gitignore）：任务的发现自动写入；risk 由三态验证驱动（confirmed 抬级 / refuted 留史不计 / unverifiable 待复核）。支持搜索、打标签、删除/合并；全部完成后「导出报告」生成 markdown 汇总。

## 接口速查

- `GET /` — 控制台单页
- `POST /api/jobs` `{type: scan | verify | agent | chain | util(action=…)}`；agent 可带 `resume_session:"last"`、`model`、`fence`、`isolate`
  - `chain`：EXP 自动关联（`url`）
  - `util` action：`revshell` / `spray` / `secret` / `screenshot` / `idor` / `oast_start|oast_poll|oast_stop` / `redis` / `ldap` / `mongo`
- `GET /api/jobs`；`GET /api/jobs/<id>`；`POST /api/jobs/<id>/cancel | interrupt | resume`（interrupt/resume 仅 agent）
- `POST /api/nlp`（自然语言→动作）；`GET /api/menu`；`GET /api/panel/<cmd>`；`GET /api/mcp` + `POST /api/mcp/toggle`
- `GET /api/stats` `GET /api/assets`；`POST /api/assets/tags|delete|merge`；`GET /api/report?full=1[&download=1]`

## 配置与约束

- `HEXSTRIKE_CONCURRENCY`（默认 3）＝并行任务上限；`DEEPSEEK_API_KEY` 提升 NL 解析质量。
- Agent 模式依赖 `claude` CLI 在 PATH 且能取到 user-scope hexstrike MCP 配置；MCP 会话级开关只管 console 发起的 agent，不影响当前 Claude 会话。
- 无人值守（launchd 定时自跑）需要代理常驻。