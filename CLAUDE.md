# HexStrike AI MCP (v7.0)

AI 渗透测试工具编排平台：Claude Code 经 MCP(stdio) 连到本服务，服务在本地 `subprocess` 调用安全工具。自包含单进程，无外部 server。

## 关键文件

- `hexstrike_mcp.py` — 主 MCP 服务（v7.0，唯一入口）。工具处理三层：`ToolRegistry`(JSON 配置) → `build_tool_command`(命令构建) → `LocalExecutionEngine`(subprocess 执行)。
- `tools/*.json` — 82 个工具命令模板（binary/category/command 模板/aliases/timeout）。**2026-09-30 扩容**：① 扩容 8 个搜索/注入/指纹工具；② 第二层 Linux 侧车 4 工具（backend docker）；③ P0/P1 加 ysoserial(Java 反序列化,容器)/secretfinder(JS 密钥)/web_screenshot(headless Chrome 截图)；④ 深化批加 redis/ldap/mongosh(未授权服务检测,容器)。其中 searchsploit/commix/xsstrike/whatweb 的 binary 在 `~/.local/bin` 是 wrapper 脚本（git 克隆到 `~/.local/share/hexstrike-tools/` + venv/系统依赖），其余走 brew/pipx/go。theHarvester 曾短暂加入（2026-09-30），因新版非 TTY 下 stdout 静默且功能被 subfinder/dnsx/gau 覆盖，已删除。

## 第二层 · Linux 侧车（2026-09-30，Docker 后端）

macOS 装不了的工具（metasploit/responder/steghide）跑在固定 Docker 容器 `hexstrike-linux`（kali-rolling）里。机制：JSON 里 `"backend":"docker"` + `"container_binary"` 字段，`build_tool_command` 经 `_docker_exec()`（见 hexstrike_mcp.py）把渲染出的命令包成 `docker exec -i hexstrike-linux <cmd>`，执行层不用改。6 个 go：metasploit(硬编码模块模式)、msfvenom、responder、steghide、msfconsole(resource 脚本模式，@mcp.tool `msf_console_run`)、privesc_extract（`docker cp` 把 `/opt/privesc/` 的提权脚本拷到 `~/hexstrike-ai/privesc/`）。

**远程执行通道（2026-09-30，remote.py）**：`remote_exec`(paramiko SSH——SFTP 上传提权脚本到已攻陷 Linux 主机→chmod +x→运行→拉回 stdout；也支持任意命令模式) + `privesc_deliver`(无 SSH 目标时生成 python http.server→curl|bash 投放命令)。脚本从 `~/hexstrike-ai/privesc/` 读（`privesc_extract` 从容器 `/opt/privesc/` 拷来）。认证：口令或 `~/.ssh/id_ed25519`（可覆盖）。依赖 paramiko（已装 hexstrike-env）。⚠️ 密码走参数、不落日志。本地测试用 `linuxserver/openssh-server` 容器冒烟通过。隔离在 remote.py，主文件只留薄 @mcp.tool。

- 容器：`docker run -d --name hexstrike-linux --restart unless-stopped kalilinux/kali-rolling sleep infinity`，装 metasploit-framework/responder/steghide/git/curl；提权脚本在 `/opt/privesc/`（linpeas.sh、pspy64s、les/linux-exploit-suggester.sh）。机器重启后 Docker Desktop 会拉起它（--restart unless-stopped）。
- **apt 源坑（关键）**：kali 默认源经 Clash 代理会响应损坏（File has unexpected size, mirror sync in progress?）；已把 `/etc/apt/sources.list.d/kali.sources` 改为 **USTC http 镜像**（`http://mirrors.ustc.edu.cn/kali`，不用 https 免 cert 问题），容器内装包先 `env -u https_proxy -u http_proxy`（走国内镜像直连，不走 7897）。CA key 在 `/etc/apt/trusted.gpg.d/kali-archive-keyring.gpg` 自动生效，无需 Signed-By。清华 https 镜像因无 ca-certificates 会 cert verify fail。
- `hexstrike_server.py` — ⚠️ 已废弃 v6.0 Flask 版，2026-09-17 已删除（git 历史可恢复）。
- `hexstrike-env/` — Python venv，已加 `.gitignore`，不入库。
- `verifiers.py` — 「证据验证层」（改造②，**P0+P1+P2 已实施 2026-09-15**）：Finding/Verdict 契约 + 5 个独立通道验证器（open_port/exposed_path/xss/sqli/tls_misconfig）+ `verify_finding`/`verify_findings`（批量 + markdown 报告）+ `nuclei_scan_and_verify`（nuclei `-jsonl -irr` 扫描自动转 Finding → 自动验证）。设计见 `docs/evidence-layer-design.md`。验证会对目标真实发 1–3 次请求。
- `memory.py` — 「轻量跨任务记忆」（改造③，**已实施 2026-09-15**）：单 JSON 资产快照 `AssetSnapshot`（URL/host 规范化、`target|port|protocol` 服务级去重、upsert 合并、三态驱动风险演算、查询、markdown 报告）+ `snapshot_update`/`query_assets`/`snapshot_report` 三个工具。设计见 `docs/cross-task-memory-design.md`。并发写：`save(remove=None)` 持 `<快照>.lock` flock + merge-on-write（锁内重读磁盘、显式删除意图、同 key 按 finding id 并集），`load()` 自愈 `_meta.count`；见设计文 §5.1。快照默认 `ai-security-snapshot.json`（已 .gitignore）。改它别动主文件。
- `dashboard.py` — 「本地 Web 控制台」（改造④-交互，**已实施 2026-09-15**）：零依赖单页交互 UI（frontend-design「界面即命令」）。**可执行**：发起扫描/验证（nuclei→自动复验）、后台 job 轮询进度、自动写资产快照、资产增删/标签/合并、报告导出、mono 活动日志（每一步留可复现命令）。**自然语言驱动**：顶部指令框走 `POST /api/nlp`（见 `nlp.py`）。**Agent 自主任务**：`POST /api/jobs` `type=agent` 起 **headless `claude -p`**（`--permission-mode bypassPermissions` 免审批）——复用现有 Claude agent 框架做多轮规划：自己调工具、写快照、结束中文总结，事件流经 stream-json 转前端日志。**多轮交互（2026-09-20）**：运行中可「⏸ 中断」（`POST /api/jobs/<id>/interrupt` → status=paused，会话保留）→ 控制台输入调整 → 「▶ 继续」（`POST /api/jobs/<id>/resume` `{text}`，`claude -p --resume <session_id>` 同一会话带记忆续跑），状态 running/paused/done/error/cancelled。**续上一会话**：再提交新目标默认**重开新会话**；勾选「🔗 续上一会话」则 `POST /api/jobs {type:"agent", resume_session:"last"}` 复用最近一次 agent 会话 id（哪怕已 done 也能 `--resume` 继续），同一攻防对话可无限续。展示：统计/风险/资产表/finding·verdict 详情。仅绑 127.0.0.1。控制台为**单入口独立进程**：MCP 工具 `start_dashboard`/`stop_dashboard` 走 `spawn_dashboard`/`stop_dashboard_process`（端口幂等复用、按端口 lsof 停，等同 shell `hexdash`），线程版保留给测试与 `__main__`。执行复用 verifiers/memory，不重写执行层。**2026-09-21 加固**：① **单一活动任务**——`_Jobs.active_job` 对 running/paused 阻塞新任务（`POST /api/jobs`/NLP 扫描类返回 409），前端三入口 `setBusy` 同锁、日志顶部标当前任务、`cancel` 支持暂停 agent；**2026-09-30 升级为并行池**——`_Jobs.MAX_RUNNING`（env `HEXSTRIKE_CONCURRENCY`，默认 3），`can_accept()` 只在满池时 409；前端**任务卡片并行**（`#cards`）：每个 job 一张独立卡片（`#jobCount` 显示 N/M 在跑），卡片自带独立日志区 + 各自的 ⏸中断/调整输入框/▶继续/✖取消，interrupt→resume 严格绑定本卡 job_id，杜绝"继续对应哪个任务"的混乱；提交按钮不禁用（服务端把关）。旧 `agentCtl`/`aadj`/`aint/ares`/`stop` 全局控件已移除（卡片替代）。**操作逻辑 IA（2026-09-30）**：左侧三块——「使用流程」引导卡（①②③：输入目标→自主任务跑主线→活动日志/快照看结果）＋「起手·自主任务」（推荐主线，`useTgt` 一键把目标填进自主任务）＋「手动工具·精确档位」按阶段分组（侦察EXP / 漏洞喷洒与OAST盲测 / 利用反连与未授权 / 逻辑IDOR / 取证JS密钥与截图）；手动工具全走 job kind `chain`/`util` 在并行池内各开任务卡（新增 util 分支：spray/secret/screenshot）。任务展示统一 `KIND` 映射（agent→自主任务/scan→扫描/…）消灭"Agent agent"。**上下文隔离开关**：agent 任务默认勾选「🗂 隔离上下文」——`claude -p` 工作目录用 `.agent/<会话id>`（`_agent_cwd`），项目级 auto-memory（`~/.claude/projects/...memory/`）按任务隔离，并行任务互不污染记忆；不勾则共享（平台根目录）。续跑 `--resume` 复用同一 `job.cwd` 保证读回原记忆；user 级 auto-memory 始终共享。`.agent/` 已 .gitignore。② **自主任务框＝claude 命令行**——整段透传（`/技能`→SKILL.md 注入 `--append-system-prompt-file`、`--model`/`--allowedTools` 透传、锁 `--output-format stream-json`）；③ **`/` 菜单 `/api/menu`**（类别词 `/skills`/`/mcp`=服务器/`/tools`=192 工具）+ **命令面板 `/api/panel/<cmd>`**（mcp 开关 / skills 预览 / model / config / memory / 一键动作）；④ **MCP 会话级开关** `/api/mcp/toggle`→`mcp-servers-state.json`→headless 生成 `--mcp-config`（只管 console 发的 agent，不影响当前会话）。
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
- `/` 菜单的 MCP 工具只列 `@mcp.tool` 函数名（192 个），`tools/*.json` 的模板名是内部 build 键（如 `amass` ≠ `amass_scan`），不可调用，别混进菜单。

## 第三层 · OAST / 隧道 / Java-OA / JS（2026-09-30,P0+P1）

- **oast.py（interactsh OAST）**：`oast_start`(起 client 取唯一域名)/`oast_poll`(拉 DNS/HTTP 回显)/`oast_stop`。把域名嵌进 blind SSRF/XXE/XSS payload，收到回调即坐实"疑似漏洞"。client 走本机 Clash 代理连 oast.* 服务；`interactsh-client` 在 `~/.local/bin`。
- **tunnel.py（chisel 反向 SOCKS）**：`chisel_tunnel`(起 server + 生成目标端 client 命令)/`chisel_stop`/`proxychains_scan`(隧道内跑 nmap/nuclei/netexec/curl)。本机 `chisel`(darwin)+ 目标用 `~/hexstrike-ai/bin/chisel-linux-amd64`。已实测 socks5 转发出网（proxychains curl 200）。
- **ysoserial（容器）**：Java 反序列化 gadget，`ysoserial_payload(gadget, command)` 输出 base64。容器已装 java 25 + jar 在 `/opt/ysoserial-all.jar`，模板带 `--add-opens` 兼容现代 JDK；用 URLDNS 冒烟出标准序列化 head。
- **secretfinder（JS 密钥）**：扫 JS 硬编码密钥/API key，wrapper → vendored venv（requests/bs4/lxml/jsbeautifier）。
- **web_screenshot**：headless Chrome 全页 PNG（wrapper，落 `~/hexstrike-ai/screenshots`，已 .gitignore）。
- **nuclei 本地模板**：`~/hexstrike-ai/nuclei-templates`（git clone，.gitignore），nuclei.json 固定 `-duc`（禁联网更新），`nuclei_update_templates` 工具 git pull 保鲜；xxe≈50/ssti≈38/ssrf≈221 模板即开即用。

## 第四层 · 深化批（2026-09-30）：反连/EXP关联/喷洒/未授权/越权

- **反连快通道**（revshell.py + listener.py）：`revshell_generate(ip,port,technique)` 一行生成 bash/nc/python/perl/ruby/php/openssl(加密)/powershell/windows-mshta 反连；`listener_start/poll/stop`（nc 或容器 msf handler）收连接、轮询日志。实测 nc 监听收到连接。
- **EXP 自动关联**（attackchain.py）：`attack_chain(url)` whatweb 指纹 → 组件映射（Shiro/ThinkPHP/WP/Tomcat/Struts/WebLogic/Drupal/Joomla/pyAdmin/Laravel/GitLab/Jenkins/nginx/iis...）→ 自动查 searchsploit(离线) + 接 nuclei tags + msf 模块 → 出"组件→可打 EXP"清单。Shiro 检测靠 `curl -D -` 的 rememberMe 头。实测本地 Apache+PHP7.4.3+Shiro 全检出。搜 EXP 是离线/有网都行（本机包）。
- **定向喷洒**（sprays.py）：`web_login_spray` 弱口令 POST 喷洒，form/json 两种 body、内置常见弱口令表、`pause_ms` 限速、429/403/401 自动停、`fail_indicator`/Location 判定成功。⚠️ 成功判定是启发式，实战需按站点调 fail_indicator。
- **未授权服务**（容器 docker 工具）：`redis_unauth`(redis-cli info)、`ldap_search`(ldapsearch 匿名 bind)、`mongo_unauth`(mongo listDatabases)。ldap 用公共测试服 ldap.forumsys.com 实测匿名 LDIF 拉取。
- **IDOR 越权**（idor.py）：`idor_check(base_url 含 {id})` 对每个 id 用高/低权 cookie、匿名三种视角差分响应，体积近似即告警。实测漏洞版服务器全命中。
- 注意：mongosh 在 kali 源是旧版 `mongo`（mongodb-clients），模板已适配。

## MCP 集成（Claude Code）

- 注册在 user scope `~/.claude.json` → `mcpServers.hexstrike-ai`（stdio，`hexstrike-env/bin/python3 hexstrike_mcp.py`），会话启动自动拉起。
- 无 Stop hook（2026-09-10 起已删）：原 Stop hook 每轮末尾杀本会话 hexstrike，是"会话中途工具掉线"根因；现跨轮常驻，会话退出随 stdin EOF 自清。残留手动清：`ps -eo pid,args | grep '[h]exstrike_mcp.py' | awk -v me=$$ '$1!=me{print $1}' | xargs kill`；勿用全局 `pkill -f`。
- 进程被杀/崩溃后需 `/mcp` 重连或重启会话，不会自动重拉。

## 调试

```bash
cd ~/hexstrike-ai && ./hexstrike-env/bin/python3 hexstrike_mcp.py    # MCP 服务前台运行
hexdash / hexdash stop    # Web 控制台一键启停（任意终端，独立进程；见 docs/web-console.md）
```