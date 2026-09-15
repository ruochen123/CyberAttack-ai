# HexStrike Web 控制台（改造④）— 使用说明

> 状态：**已实施（2026-09-15，NL + Agent 驱动 2026-09-16）** ｜ 前端视觉：frontend-design「界面即命令」
> 依赖：Python 3.10+（标准库）＋ `claude` CLI 在 PATH（Agent 模式用）＋ 可选 `DEEPSEEK_API_KEY`（NL 更强解析）
> 只对 **127.0.0.1** 监听（本机使用）；扫描/验证会对目标真实发请求，**仅用于已授权目标**。

## 启动

```bash
cd ~/hexstrike-ai
./hexstrike-env/bin/python3 dashboard.py          # 独立进程，默认 :8765，自动开浏览器
# 端口/快照自定：dashboard.py <snapshot_path> 或改 DEFAULT_PORT
```

也可以经 MCP 工具启停（Claude 会话内）：`start_dashboard(port=8765, open_browser=True)` / `stop_dashboard(port=8765)`。同端口重复调用复用实例。

打开 `http://127.0.0.1:8765/` 即控制台。

## 三种操作模式

形成「人工表单 → 自然语言 → 全自主」三级：

1. **表单**：左侧面板填目标/扫描类型/severity/tags/template → 执行。后台 job 轮询进度，完成后自动写资产快照。
2. **自然语言指令框**（`POST /api/nlp`）：如「扫描 https://example.com:8443 的高危 xss」「给 app-server 加 redteam 标签」「资产统计」。逻辑在 `nlp.py`：优先 DeepSeek chat 解析（配 `DEEPSEEK_API_KEY`），无 key/失败回退本地关键词规则。
3. **Agent 自主任务框**（`POST /api/jobs` `type=agent`）：给一句目标，控制台起 **headless `claude -p`** 子进程，复用现有 Claude agent 框架做多轮规划——自己调 hexstrike 工具（探活/枚举/验证/写快照）、结束中文总结；工具调用与结论实时流进活动日志。护栏：`--allowedTools mcp__hexstrike-ai__*`（只放 hexstrike 工具，不放开 shell/exec 等）。

## 页面与接口

- `GET /` — 控制台单页（统计条 / 风险 / 资产表 / finding·verdict 详情，点击资产行展开复现命令与证据哈希；搜索 + 风险筛选）
- `GET /api/stats` `GET /api/assets` — 资产快照（每次请求重读 `ai-security-snapshot.json`，与 agent 等其它进程共享最新数据）
- `GET /api/report?full=1[&download=1]` — markdown 报告 / 下载
- `POST /api/jobs` `type=scan | verify | agent`；`GET /api/jobs/<id>` 轮询；`POST /api/jobs/<id>/cancel`
- `POST /api/nlp` `{text}` — 自然语言 → 动作
- `POST /api/assets/tags | delete | merge` — 资产管理

## 数据与风险演算

快照默认 `ai-security-snapshot.json`（`.gitignore` 已排除）。risk 由三态验证驱动：`confirmed` 抬级别、`refuted` 留历史不计、`unverifiable` 计待复核。每个动作的活动日志保留可复现命令 ―— 「界面即命令」。

## 已知约束

- Agent 模式依赖 `claude` 能取到 user-scope MCP 配置（hexstrike 自动拉起），模型链路与当前会话一致（本机代理）。
- 无人值守（launchd 定时自跑）需要代理常驻；要离线自治可把 `nlp.py`/agent 的模型层切 DeepSeek 直连（当前 NL 已支持）。
- 设计背景对照：为什么不整体换平台（PentAGI / CyberStrikeAI）见 CLAUDE.md 里改造清单的说明。