# HexStrike Web 控制台（改造④）— 使用说明

> 状态：**已实施（2026-09-15，NL + Agent 驱动 2026-09-16）** ｜ 前端视觉：frontend-design「界面即命令」
> 依赖：Python 3.10+（标准库）＋ `claude` CLI 在 PATH（Agent 模式用）＋ 可选 `DEEPSEEK_API_KEY`（NL 更强解析）
> 只对 **127.0.0.1** 监听（本机使用）；扫描/验证会对目标真实发请求。

## 启动

**一键（推荐，任意终端）：**

```bash
hexdash             # 启动 :8765，自动开浏览器；已在运行则复用
hexdash stop        # 停止
```

`hexdash` 定义在 `~/.zshrc`，实际是 `nohup dashboard.py` 起**独立进程**（PPID=1、日志 /tmp/hexdash.log），不受 Claude 会话/MCP 影响。等价直接跑：

```bash
cd ~/hexstrike-ai && ./hexstrike-env/bin/python3 dashboard.py
```

也可以经 MCP 工具启停（Claude 会话内）：`start_dashboard(port=8765)` / `stop_dashboard(port=8765)`。2026-09-17 起 MCP 工具与 `hexdash` 同为**独立进程形态**（走 `spawn_dashboard`/`stop_dashboard_process`，端口幂等复用、按端口停止），已无"会话内线程、随会话退出"的旧行为，MCP 断开不影响控制台。

打开 `http://127.0.0.1:8765/` 即控制台。

## 三种操作模式

形成「人工表单 → 自然语言 → 全自主」三级：

1. **表单**：左侧面板填目标/扫描类型/severity/tags/template → 执行。后台 job 轮询进度，完成后自动写资产快照。
2. **自然语言指令框**（`POST /api/nlp`）：如「扫描 https://example.com:8443 的高危 xss」「给 app-server 加 redteam 标签」「资产统计」。逻辑在 `nlp.py`：优先 DeepSeek chat 解析（配 `DEEPSEEK_API_KEY`），无 key/失败回退本地关键词规则。
3. **Agent 自主任务框**（`POST /api/jobs` `type=agent`）：给一句目标，控制台起 **headless `claude -p`**（`--permission-mode bypassPermissions`）子进程，复用现有 Claude agent 框架做多轮规划——自己调 hexstrike 工具（探活/枚举/验证/写快照）、结束中文总结；工具调用与结论实时流进活动日志。**输入框就是 claude 命令行**：
   - 整段 = `claude -p` 参数：`/技能名`、前置 flag（`--model`/`--max-turns`/`--allowedTools` 等原样透传）、首个非 flag 词起为 prompt，纯文本用法与旧版一致；
   - **输入 `/` 即弹 TUI 式分组菜单**（`/api/menu`）：`/` 默认列 命令 + 技能·插件（带 frontmatter 描述）；类别词整组展开——`/skills`（技能清单）、`/mcp`（2 台 MCP **服务器**，非单个工具）、`/tools`（158 个 `mcp__hexstrike-ai__*` 工具）、`/plugin`（插件技能）、`/cmd`（命令）；其它前缀跨组过滤；↑↓ + Enter 选择、Esc 关闭；
   - `/neat-freak 整理文档` → 控制台定位 `SKILL.md` 确定性注入 `--append-system-prompt-file`（不靠模型自己判断）；内置/插件技能无本地文件时优雅降级，保留原文并引导模型走 Skill 工具；
   - 保留项硬控：`--output-format` 锁 `stream-json`、`--session-id`/`--resume` 由控制台记账（`--session-id` 手动传可覆盖）、默认 `--permission-mode bypassPermissions`（文本可覆盖）；
   - 模型下拉 → `--model`（新任务与「继续」均生效）；勾选「工具白名单」+ 逗号分隔列表 → 注入 `--allowedTools`（名单外工具拒绝，拒绝记录进日志）。
   - **单一活动任务**：任一任务 running/paused 时，新任务（表单/NLP/Agent 三入口统一）返回 409「先完成或停止它」；前端三入口 `setBusy` 同锁禁用、`stop` 可停止（含暂停的 agent）；日志顶部标注「▶ 当前任务 job…」。
   - **命令面板（`/api/panel/<cmd>`）**：命令组选中 `/mcp` `/skills` `/model` `/config` `/memory` 等即弹 TUI 式对话框——mcp 服务器开关、技能 SKILL.md 预览（内置无文件标灰）、模型选择、配置/记忆/agents/上下文目录清单、`/clear` `/resume` 一键动作。
   - **MCP 服务器会话级开关**：`/api/mcp` + `/api/mcp/toggle`，状态存 `mcp-servers-state.json`（已 .gitignore，不改全局 `~/.claude.json`）；有停用时控制台发起 agent 生成 `--mcp-config` 只连启用服务器。管的是「console 发起的 agent」，不影响当前 Claude 会话。
   **多轮交互**：运行中可随时「⏸ 中断」（`/api/jobs/<id>/interrupt`，status 转 paused、会话保留）→ 在输入框写调整指令（留空=直接继续）→「▶ 继续」（`/api/jobs/<id>/resume`，`claude -p --resume <session_id>` 同一会话带记忆续跑）。会话以 `--session-id <uuid>` 创建，中断后可按需反复 调整→继续。**续上一会话**：重复提交目标默认重开新会话（每次新建 session-id，仅读快照兜底）；勾选「🔗 续上一会话」→ `POST /api/jobs` 带 `resume_session:"last"`，复用最近一次 agent 会话 id（含已完成的会话，`claude -p --resume` 继续），同一攻防对话可无限续。

## 页面与接口

- `GET /` — 控制台单页（统计条 / 风险 / 资产表 / finding·verdict 详情，点击资产行展开复现命令与证据哈希；搜索 + 风险筛选）
- `GET /api/stats` `GET /api/assets` — 资产快照（每次请求重读 `ai-security-snapshot.json`，与 agent 等其它进程共享最新数据）
- `GET /api/report?full=1[&download=1]` — markdown 报告 / 下载
- `GET /api/menu` — `/` 菜单（命令/技能·插件/MCP 工具/其它服务器）
- `GET /api/panel/<cmd>` — 命令面板（mcp|skills|model|permissions|config|memory|agents|add-dir|clear|compact|resume|rewind）
- `GET /api/mcp` `POST /api/mcp/toggle` — MCP 服务器状态 / 会话级开关（`mcp-servers-state.json`）
- `GET /api/skills` `GET /api/skill/read?name=` — 技能清单（frontmatter 描述/路径）与 SKILL.md 预览
- `POST /api/jobs` `type=scan | verify | agent`（agent 可带 `resume_session:"last"` 续上一会话、`model`、`fence`）；`GET /api/jobs/<id>` 轮询；`POST /api/jobs/<id>/cancel | interrupt | resume`（interrupt/resume 仅 agent：interrupt → status=paused 保留会话，resume 带 `{text, model, fence}` 调整续跑）
- `POST /api/nlp` `{text}` — 自然语言 → 动作
- `POST /api/assets/tags | delete | merge` — 资产管理

## 数据与风险演算

快照默认 `ai-security-snapshot.json`（`.gitignore` 已排除）。risk 由三态验证驱动：`confirmed` 抬级别、`refuted` 留历史不计、`unverifiable` 计待复核。每个动作的活动日志保留可复现命令 ―— 「界面即命令」。

## 已知约束

- Agent 模式依赖 `claude` 能取到 user-scope MCP 配置（hexstrike 自动拉起），模型链路与当前会话一致（本机代理）。
- 无人值守（launchd 定时自跑）需要代理常驻；要离线自治可把 `nlp.py`/agent 的模型层切 DeepSeek 直连（当前 NL 已支持）。
- 设计背景对照：为什么不整体换平台（PentAGI / CyberStrikeAI）见 CLAUDE.md 里改造清单的说明。