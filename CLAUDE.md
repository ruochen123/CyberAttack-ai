# HexStrike AI MCP (v7.0)

AI 渗透测试工具编排平台：Claude Code 经 MCP(stdio) 连到本服务，服务在本地 `subprocess` 调用安全工具。自包含单进程，无外部 server。

## 关键文件

- `hexstrike_mcp.py` — 主 MCP 服务（v7.0，唯一入口）。工具处理三层：`ToolRegistry`(JSON 配置) → `build_tool_command`(命令构建) → `LocalExecutionEngine`(subprocess 执行)。
- `tools/*.json` — 67 个工具命令模板（binary/category/command 模板/aliases/timeout）。
- `hexstrike_server.py` — ⚠️ 已废弃 v6.0 Flask 版，2026-09-17 已删除（git 历史可恢复）。
- `hexstrike-env/` — Python venv，已加 `.gitignore`，不入库。
- `verifiers.py` — 「证据验证层」（改造②，**P0+P1+P2 已实施 2026-09-15**）：Finding/Verdict 契约 + 5 个独立通道验证器（open_port/exposed_path/xss/sqli/tls_misconfig）+ `verify_finding`/`verify_findings`（批量 + markdown 报告）+ `nuclei_scan_and_verify`（nuclei `-jsonl -irr` 扫描自动转 Finding → 自动验证）。设计见 `docs/evidence-layer-design.md`。验证会对目标真实发 1–3 次请求。
- `memory.py` — 「轻量跨任务记忆」（改造③，**已实施 2026-09-15**）：单 JSON 资产快照 `AssetSnapshot`（URL/host 规范化、`target|port|protocol` 服务级去重、upsert 合并、三态驱动风险演算、查询、markdown 报告）+ `snapshot_update`/`query_assets`/`snapshot_report` 三个工具。设计见 `docs/cross-task-memory-design.md`。并发写：`save(remove=None)` 持 `<快照>.lock` flock + merge-on-write（锁内重读磁盘、显式删除意图、同 key 按 finding id 并集），`load()` 自愈 `_meta.count`；见设计文 §5.1。快照默认 `ai-security-snapshot.json`（已 .gitignore）。改它别动主文件。
- `dashboard.py` — 「本地 Web 控制台」（改造④-交互，**已实施 2026-09-15**）：零依赖单页交互 UI（frontend-design「界面即命令」）。**可执行**：发起扫描/验证（nuclei→自动复验）、后台 job 轮询进度、自动写资产快照、资产增删/标签/合并、报告导出、mono 活动日志（每一步留可复现命令）。**自然语言驱动**：顶部指令框走 `POST /api/nlp`（见 `nlp.py`）。**Agent 自主任务**：`POST /api/jobs` `type=agent` 起 **headless `claude -p`**（`--permission-mode bypassPermissions` 免审批）——复用现有 Claude agent 框架做多轮规划：自己调工具、写快照、结束中文总结，事件流经 stream-json 转前端日志。**多轮交互（2026-09-20）**：运行中可「⏸ 中断」（`POST /api/jobs/<id>/interrupt` → status=paused，会话保留）→ 控制台输入调整 → 「▶ 继续」（`POST /api/jobs/<id>/resume` `{text}`，`claude -p --resume <session_id>` 同一会话带记忆续跑），状态 running/paused/done/error/cancelled。**续上一会话**：再提交新目标默认**重开新会话**；勾选「🔗 续上一会话」则 `POST /api/jobs {type:"agent", resume_session:"last"}` 复用最近一次 agent 会话 id（哪怕已 done 也能 `--resume` 继续），同一攻防对话可无限续。展示：统计/风险/资产表/finding·verdict 详情。仅绑 127.0.0.1。控制台为**单入口独立进程**：MCP 工具 `start_dashboard`/`stop_dashboard` 走 `spawn_dashboard`/`stop_dashboard_process`（端口幂等复用、按端口 lsof 停，等同 shell `hexdash`），线程版保留给测试与 `__main__`。执行复用 verifiers/memory，不重写执行层。**2026-09-21 加固**：① **单一活动任务**——`_Jobs.active_job` 对 running/paused 阻塞新任务（`POST /api/jobs`/NLP 扫描类返回 409），前端三入口 `setBusy` 同锁、日志顶部标当前任务、`cancel` 支持暂停 agent；② **自主任务框＝claude 命令行**——整段透传（`/技能`→SKILL.md 注入 `--append-system-prompt-file`、`--model`/`--allowedTools` 透传、锁 `--output-format stream-json`）；③ **`/` 菜单 `/api/menu`**（类别词 `/skills`/`/mcp`=服务器/`/tools`=158 工具）+ **命令面板 `/api/panel/<cmd>`**（mcp 开关 / skills 预览 / model / config / memory / 一键动作）；④ **MCP 会话级开关** `/api/mcp/toggle`→`mcp-servers-state.json`→headless 生成 `--mcp-config`（只管 console 发的 agent，不影响当前会话）。
- `nlp.py` — 「自然语言 → 动作」（改造④-NL，**已实施**）：把指令解析为动作 schema（scan/verify/tag/delete/merge/report/stats）。优先 DeepSeek chat（`response_format json`，env `DEEPSEEK_API_KEY`），无 key 或调用失败回退本地关键词规则；`target`/`severity`/`tags`/JSON 提取。规则模式够大多数命令；要更强理解配好 key 即可。

## 加新工具（改 tools/ 就够）

写 `tools/<name>.json` + 装 binary（PATH 里即可，无路径映射）+ 加 `@mcp.tool` 签名。命令构建器不要改。

装 binary 的常用来源：brew（→`/opt/homebrew/bin`）、pipx（→`~/.local/bin`）、`cargo install`（→`~/.cargo/bin`）、`go install`（**必须先 `go env -w GOBIN=$HOME/.local/bin`**，否则落 `~/go/bin` 而该目录不在 PATH，表现为"装了但 health_check 仍报缺失"）。

## 已知坑

- `ToolRegistry.get()` 对含 `-`/`_` 的工具名（如 `arp-scan`、`generic_web_proxy`）必须走原始名精确匹配分支，否则返回 None 调不通。
- `build_tool_command` 4 级优先：ToolRegistry JSON → 硬编码(hydra/john/hashcat/sqlmap/ffuf/metasploit) → generic web proxy curl 兜底 → legacy command 字段。
- Agent 自主任务依赖 `claude` CLI 在 PATH（headless `claude -p`），且需能取到 user-scope hexstrike MCP 配置；缺任一则 agent job 报错。
- 控制台多进程共享快照：agent（headless 里的 hexstrike worker）写盘后，dashboard 每个请求重读 `ai-security-snapshot.json` 即同步；大改快照结构只在 memory.py。
- Web 控制台里用 `hidden` 属性控显隐的元素（`#uxModal`、`#skillMenu`），CSS 不能写 `display:flex`（优先级会压过 `hidden` 的 `display:none`，导致**常显卡死全屏**）；要 flex 用 `#xx:not([hidden]){display:flex}`。2026-09-21 `#uxModal` 曾踩。
- `/` 菜单的 MCP 工具只列 `@mcp.tool` 函数名（158 个），`tools/*.json` 的模板名是内部 build 键（如 `amass` ≠ `amass_scan`），不可调用，别混进菜单。

## MCP 集成（Claude Code）

- 注册在 user scope `~/.claude.json` → `mcpServers.hexstrike-ai`（stdio，`hexstrike-env/bin/python3 hexstrike_mcp.py`），会话启动自动拉起。
- 无 Stop hook（2026-09-10 起已删）：原 Stop hook 每轮末尾杀本会话 hexstrike，是"会话中途工具掉线"根因；现跨轮常驻，会话退出随 stdin EOF 自清。残留手动清：`ps -eo pid,args | grep '[h]exstrike_mcp.py' | awk -v me=$$ '$1!=me{print $1}' | xargs kill`；勿用全局 `pkill -f`。
- 进程被杀/崩溃后需 `/mcp` 重连或重启会话，不会自动重拉。

## 调试

```bash
cd ~/hexstrike-ai && ./hexstrike-env/bin/python3 hexstrike_mcp.py    # MCP 服务前台运行
hexdash / hexdash stop    # Web 控制台一键启停（任意终端，独立进程；见 docs/web-console.md）
```