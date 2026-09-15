# HexStrike AI MCP (v7.0)

AI 渗透测试工具编排平台：Claude Code 经 MCP(stdio) 连到本服务，服务在本地 `subprocess` 调用安全工具。自包含单进程，无外部 server。

## 关键文件

- `hexstrike_mcp.py` — 主 MCP 服务（v7.0，唯一入口）。工具处理三层：`ToolRegistry`(JSON 配置) → `build_tool_command`(命令构建) → `LocalExecutionEngine`(subprocess 执行)。
- `tools/*.json` — 67 个工具命令模板（binary/category/command 模板/aliases/timeout）。
- `hexstrike_server.py` — ⚠️ 已废弃的 v6.0 Flask 版，不加载、不要改/启用。
- `hexstrike-env/` — Python venv，已加 `.gitignore`，不入库。
- `verifiers.py` — 「证据验证层」（改造②，**P0+P1+P2 已实施 2026-09-15**）：Finding/Verdict 契约 + 5 个独立通道验证器（open_port/exposed_path/xss/sqli/tls_misconfig）+ `verify_finding`/`verify_findings`（批量 + markdown 报告）+ `nuclei_scan_and_verify`（nuclei `-jsonl -irr` 扫描自动转 Finding → 自动验证）。设计见 `docs/evidence-layer-design.md`。验证会对目标真实发 1–3 次请求，仅限已授权目标。
- `memory.py` — 「轻量跨任务记忆」（改造③，**已实施 2026-09-15**）：单 JSON 资产快照 `AssetSnapshot`（URL/host 规范化、`target|port|protocol` 服务级去重、upsert 合并、三态驱动风险演算、查询、markdown 报告）+ `snapshot_update`/`query_assets`/`snapshot_report` 三个工具（156 工具注册）。设计见 `docs/cross-task-memory-design.md`。快照默认 `ai-security-snapshot.json`（已 .gitignore）。改它别动主文件。
- `dashboard.py` — 「本地 Web 控制台」（改造④-交互，**已实施 2026-09-15**）：零依赖单页交互 UI（frontend-design「界面即命令」）。**可执行**：发起扫描/验证（nuclei→自动复验）、后台 job 轮询进度、自动写资产快照、资产增删/标签/合并、报告导出、mono 活动日志（每一步留可复现命令）。展示：统计/风险/资产表/finding·verdict 详情。仅绑 127.0.0.1。`start_dashboard`/`stop_dashboard`（默认 :8765，同端口复用）。执行复用 verifiers/memory，不重写执行层。

## 加新工具（改 tools/ 就够）

写 `tools/<name>.json` + 装 binary（PATH 里即可，无路径映射）+ 加 `@mcp.tool` 签名。命令构建器不要改。

装 binary 的常用来源：brew（→`/opt/homebrew/bin`）、pipx（→`~/.local/bin`）、`cargo install`（→`~/.cargo/bin`）、`go install`（**必须先 `go env -w GOBIN=$HOME/.local/bin`**，否则落 `~/go/bin` 而该目录不在 PATH，表现为"装了但 health_check 仍报缺失"）。

## 已知坑

- `ToolRegistry.get()` 对含 `-`/`_` 的工具名（如 `arp-scan`、`generic_web_proxy`）必须走原始名精确匹配分支，否则返回 None 调不通。
- `build_tool_command` 4 级优先：ToolRegistry JSON → 硬编码(hydra/john/hashcat/sqlmap/ffuf/metasploit) → generic web proxy curl 兜底 → legacy command 字段。

## MCP 集成（Claude Code）

- 注册在 user scope `~/.claude.json` → `mcpServers.hexstrike-ai`（stdio，`hexstrike-env/bin/python3 hexstrike_mcp.py`），会话启动自动拉起。
- 无 Stop hook（2026-09-10 起已删）：原 Stop hook 每轮末尾杀本会话 hexstrike，是"会话中途工具掉线"根因；现跨轮常驻，会话退出随 stdin EOF 自清。残留手动清：`ps -eo pid,args | grep '[h]exstrike_mcp.py' | awk -v me=$$ '$1!=me{print $1}' | xargs kill`；勿用全局 `pkill -f`。
- 进程被杀/崩溃后需 `/mcp` 重连或重启会话，不会自动重拉。

## 调试

```bash
cd ~/hexstrike-ai && ./hexstrike-env/bin/python3 hexstrike_mcp.py   # 前台运行
```