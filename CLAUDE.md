# HexStrike AI MCP (v7.0)

AI 渗透测试工具编排平台：Claude Code 经 MCP(stdio) 连到本服务，服务在本地 `subprocess` 调用安全工具。自包含单进程，无外部 server。

## 关键文件

- `hexstrike_mcp.py` — 主 MCP 服务（v7.0，唯一入口）。工具处理三层：`ToolRegistry`(JSON 配置) → `build_tool_command`(命令构建) → `LocalExecutionEngine`(subprocess 执行)。
- `tools/*.json` — 67 个工具命令模板（binary/category/command 模板/aliases/timeout）。
- `hexstrike_server.py` — ⚠️ 已废弃的 v6.0 Flask 版，不加载、不要改/启用。
- `hexstrike-env/` — Python venv，已加 `.gitignore`，不入库。
- `verifiers.py` — 「证据验证层」（改造②，**P0+P1 已实施 2026-09-15**）：Finding/Verdict 契约 + 5 个独立通道验证器（open_port/exposed_path/xss/sqli/tls_misconfig）+ `verify_finding`/`verify_findings`（批量 + markdown 报告）。设计见 `docs/evidence-layer-design.md`（P2 nuclei `-jsonl` 一条龙待做）。验证会对目标真实发 1–3 次请求，仅限已授权目标。

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