#!/usr/bin/env python3
"""HexStrike Web 控制台（改造④-交互）—— 本地可视化 + 可执行操作的交互 Web。

零第三方依赖（标准库 http.server + webbrowser）。把 HexStrike 能力搬上网页：
- 发起扫描（nuclei -jsonl → 自动验证）、校验 findings、写资产快照
- 资产增删改/合并/标签、报告导出、活动日志（mono 事件流）
数据来自 memory.AssetSnapshot；执行复用 verifiers / hexstrike_mcp.HexStrikeClient。
界面风格：审计作战室 ——「界面即命令」，动作即可复现命令事件行。
仅绑 127.0.0.1；扫描/验证会对目标真实发请求，仅用于已授权目标。
"""

import json
import os
import re
import subprocess
import threading
import urllib.parse
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import memory

DEFAULT_PORT = 8765

# --- 设计 token（frontend-design）---
RISK_COLORS = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219",
               "low": "#9a9a97", "normal": "#0ca30c", "unassessed": "#b9b8b3"}
RISK_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
              "normal": "正常", "unassessed": "未评估"}
VERDICT_COLORS = {"confirmed": "#0ca30c", "refuted": "#9a9a97", "unverifiable": "#fab219"}
VERDICT_LABEL = {"confirmed": "已复现", "refuted": "未复现", "unverifiable": "待复核"}

PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HexStrike Web Console</title>
<style>
:root{
  --bg:#0F131A; --surface:#171D27; --raise:#1F2733; --line:#2B3547;
  --ink:#E8EAF0; --ink2:#98A2B3; --ink3:#6B7585;
  --acc:#4C8DFF; --hot:#F5A623; --good:#2FB380;
  --crit:#d03b3b; --serious:#ec835a; --warn:#fab219; --ok:#0ca30c; --muted:#9a9a97;
  --mono:Menlo,Monaco,"SF Mono","Cascadia Code",monospace;
  --sans:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);
  font:13.5px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
.mono{font-family:var(--mono)}
.wrap{max-width:1280px;margin:0 auto;padding:18px 22px 70px}
/* topbar */
header{display:flex;align-items:baseline;gap:16px;border-bottom:1px solid var(--line);padding:0 0 14px}
.brand{font-family:var(--mono);font-size:19px;font-weight:650;letter-spacing:.2px}
.brand b{color:var(--acc);font-weight:650}
.conn{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--ink2);font-size:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ink3);transition:background .3s}
.dot.on{background:var(--good);box-shadow:0 0 8px var(--good)}
.sub{color:var(--ink2);font-size:12px;font-family:var(--mono)}
/* layout */
main{display:grid;grid-template-columns:minmax(360px,390px) minmax(300px,1fr) 320px;gap:16px;margin-top:16px}
@media(max-width:1120px){main{grid-template-columns:1fr 1fr}}
@media(max-width:760px){main{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:7px;overflow:hidden}
.panel h3{margin:0;padding:10px 14px;font-family:var(--mono);font-size:12px;font-weight:600;
  letter-spacing:.4px;border-bottom:1px solid var(--line);color:var(--ink2)}
.pbody{padding:14px}
/* actions */
label{display:block;font-size:12px;color:var(--ink2);margin:10px 0 4px}
input,select,textarea{width:100%;background:var(--bg);color:var(--ink);border:1px solid var(--line);
  border-radius:6px;padding:8px 10px;font:13px var(--mono)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--acc)}
textarea{resize:vertical;min-height:64px}
.hint{font-size:11px;color:var(--ink3);font-family:var(--mono);margin-top:4px}
.btn{display:inline-flex;align-items:center;gap:8px;border:none;cursor:pointer;border-radius:6px;
  padding:9px 16px;font:600 13px var(--sans);color:#0b0f16}
.btn.primary{background:var(--acc);color:#fff}
.btn.primary:disabled{opacity:.45;cursor:not-allowed}
.btn.ghost{background:var(--raise);color:var(--ink);border:1px solid var(--line)}
.btn.small{padding:4px 10px;font-size:12px;border-radius:5px;background:var(--raise);
  color:var(--ink2);border:1px solid var(--line)}
.btn.small:hover{color:var(--ink);border-color:var(--acc)}
.btnrow{display:flex;gap:8px;margin-top:12px}
/* log */
.log{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px 12px;
  font-family:var(--mono);font-size:12px;line-height:1.7;overflow:auto;max-height:430px;min-height:180px}
.log .ln{white-space:pre-wrap;word-break:break-word}
.log .t{color:var(--ink3);margin-right:6px}
.log .ok{color:var(--good)} .log .err{color:var(--serious)} .log .ac{color:var(--hot)}
/* tiles */
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
@media(max-width:760px){.tiles{grid-template-columns:repeat(2,1fr)}}
.tile{background:var(--surface2,#171D27);border:1px solid var(--line);border-radius:6px;padding:9px 11px}
.tile .num{font-family:var(--mono);font-size:21px;font-weight:650}
.tile .lbl{color:var(--ink2);font-size:11px;margin-top:1px}
/* asset table */
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{text-align:left;color:var(--ink2);font-weight:550;padding:6px 9px;border-bottom:1px solid var(--line);
  font-family:var(--mono);font-size:11px;letter-spacing:.3px}
.tbl td{padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
.tbl tbody tr:hover td{background:var(--bg)}
.tbl tbody tr.sel td{background:var(--raise)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:1px 8px;border-radius:99px;font-size:11.5px;
  border:1px solid;white-space:nowrap}
.dotb{width:7px;height:7px;border-radius:50%}
.tag{display:inline-block;background:var(--raise);border:1px solid var(--line);border-radius:4px;
  padding:0 6px;font-size:11px;margin:1px 2px;font-family:var(--mono);color:var(--ink2)}
/* findings expand */
.find{margin:6px 9px 8px;padding:10px;background:var(--bg);border:1px solid var(--line);border-radius:6px}
.find .f{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;padding:5px 0;border-bottom:1px dashed var(--line)}
.find .f:last-child{border-bottom:none}
.cmd{font-family:var(--mono);font-size:11.5px;word-break:break-all;color:var(--ace,#c6ccd8)}
.empty{color:var(--ink3);padding:16px;text-align:center;font-family:var(--mono);font-size:12px}
.toast{position:fixed;bottom:18px;right:18px;background:var(--surface);border:1px solid var(--line);
  border-radius:6px;padding:10px 14px;font-size:12.5px;opacity:0;transform:translateY(6px);
  transition:.25s;pointer-events:none;z-index:9}
.toast.show{opacity:1;transform:none}
.footer{display:flex;gap:10px;margin-top:14px}
.err{color:var(--serious);font-size:12px;font-family:var(--mono)}
</style>
</head>
<body><div class="wrap">
<header>
  <div class="brand">Hex<b>Strike</b> Web Console</div>
  <span class="sub" id="snapinfo"></span>
  <div class="conn"><span class="dot" id="cstat"></span><span id="cstatlbl">本地服务</span></div>
</header>

<main>
  <div class="panel"><h3>发起操作</h3><div class="pbody">
    <label for="nlpInput">自然语言指令</label>
    <div style="display:flex;gap:8px">
      <input id="nlpInput" placeholder="扫描 https://example.com:8443 的高危 xss">
      <button class="btn ghost" id="nlpGo" style="flex:none">执行指令</button>
    </div>
    <div class="hint">支持 扫描 / 验证 / 加标签 / 删除 / 合并 / 报告 / 统计</div>
    <label for="agoal" style="margin-top:14px">自主任务 — 交给 Claude Agent（多轮规划）</label>
    <div style="display:flex;gap:8px">
      <input id="agoal" placeholder="对 https://example.com 做侦查，验证 xss，写快照并总结">
      <button class="btn ghost" id="ago" style="flex:none">🧠 Agent 执行</button>
    </div>
    <div class="hint">Claude 自助调 hexstrike 工具规划执行（headless）。目标仅限授权。</div>
    <hr style="border:none;border-top:1px solid var(--line);margin:14px 0 2px">
    <label for="tgt">目标（URL / 域名 / IP，仅授权目标）</label>
    <input id="tgt" placeholder="https://host / host:port" value="">
    <div class="opts">
      <label for="ftype">扫描类型</label>
      <select id="ftype">
        <option value="scan">扫描并验证（nuclei → 自动复验）</option>
        <option value="verify">仅独立验证 findings（JSON）</option>
      </select>
    </div>
    <div id="scanOpts">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <div><label for="sev">severity</label><input id="sev" placeholder="high,medium" value=""></div>
        <div><label for="tags">tags</label><input id="tags" placeholder="xss,sqli" value=""></div>
      </div>
      <label for="tmpl">template（-t，可选）</label><input id="tmpl" placeholder="/path/template.yaml">
      <label for="extra">additional args</label><input id="extra" placeholder="-rl 20">
    </div>
    <div id="verifyOpts" hidden>
      <label for="fjs">findings（JSON 数组 / JSONL）</label>
      <textarea id="fjs" placeholder='[{"target":"https://host","type":"xss","matched_at":"https://host/a?id=1","severity":"high"}]'></textarea>
    </div>
    <div class="btnrow">
      <button class="btn primary" id="go">▶ 执行</button>
      <button class="btn ghost" id="stop" disabled>停止</button>
    </div>
    <div class="hint">action 会真实发请求；每一步都留可复现命令</div>
  </div></div>

  <div class="panel"><h3>活动日志</h3><div class="pbody">
    <div class="log" id="log"><div class="ln"><span class="t"></span>▸ 就绪 — 在此发起扫描与验证</div></div>
    <div class="footer">
      <button class="btn ghost small" id="exp">导出 markdown 报告</button>
      <button class="btn ghost small" id="clr">清空日志</button>
    </div>
  </div></div>

  <div class="panel"><h3>资产快照</h3><div class="pbody">
    <div class="tiles">
      <div class="tile"><div class="num" id="tTotal">–</div><div class="lbl">资产</div></div>
      <div class="tile"><div class="num" id="tVuln">–</div><div class="lbl">确认漏洞</div></div>
      <div class="tile"><div class="num" id="tPend">–</div><div class="lbl">待复核</div></div>
      <div class="tile"><div class="num" id="tHigh">–</div><div class="lbl">高危以上</div></div>
    </div>
    <div class="btnrow" style="margin-top:0;margin-bottom:10px">
      <input id="q" placeholder="搜索…" style="width:auto;flex:1">
      <button class="btn ghost small" id="bAddTag">+标签</button>
      <button class="btn ghost small" id="bDel">删除选中</button>
      <button class="btn ghost small" id="bMerge">合并选中</button>
    </div>
    <div style="overflow:auto;max-height:600px">
    <table class="tbl"><thead><tr><th></th><th>目标</th><th>端口</th><th>风险</th><th>漏洞</th><th>待复核</th><th>tags</th></tr></thead>
    <tbody id="rows"><tr class="empty" id="empty" hidden><td colspan="7">快照为空 — 先发起一次操作</td></tr></tbody></table>
    </div>
  </div></div>
</main>
</div>
<div class="toast" id="toast"></div>

<script>
const RL={critical:"严重",high:"高危",medium:"中危",low:"低危",normal:"正常",unassessed:"未评估"};
const RC={critical:"#d03b3b",high:"#ec835a",medium:"#fab219",low:"#9a9a97",normal:"#0ca30c",unassessed:"#b9b8b3"};
const VL={confirmed:"已复现",refuted:"未复现",unverifiable:"待复核"};
const VC={confirmed:"#0ca30c",refuted:"#9a9a97",unverifiable:"#fab219"};
let assets=[],curJob=null,pollT=null;
const $=id=>document.getElementById(id);
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function toast(msg){const t=$("toast");t.textContent=msg;t.classList.add("show");clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove("show"),2600);}
function log(cls,msg){const l=$("log");const ln=document.createElement("div");ln.className="ln";
  ln.innerHTML=`<span class="t">${new Date().toTimeString().slice(0,8)}</span><span class="${cls}">${esc(msg)}</span>`;
  l.appendChild(ln);l.scrollTop=l.scrollHeight;}
async function api(path,opts){const r=await fetch(path,opts);const j=await r.json();
  if(!r.ok)throw new Error(j.error||("HTTP "+r.status));return j;}
function riskBadge(r){return `<span class="badge" style="color:${RC[r]};border-color:${RC[r]}"><span class="dotb" style="background:${RC[r]}"></span>${RL[r]}</span>`;}
async function loadAssets(){
  try{const s=await api("/api/stats");
    $("tTotal").textContent=s.total_assets;$("tVuln").textContent=s.total_confirmed;
    $("tPend").textContent=s.pending_review;$("tHigh").textContent=(s.by_risk.critical||0)+(s.by_risk.high||0);
    $("snapinfo").textContent="快照 "+(s.updated_at||"-").replace("T"," ").slice(0,19);
    assets=await api("/api/assets");render();
  }catch(e){log("err","资产载入失败："+e.message);}
}
function render(){
  const q=($("q").value||"").trim().toLowerCase();
  const pool=assets.filter(a=>!q||(a.target+" "+a.tags.join(" ")+" "+a.port).toLowerCase().includes(q));
  $("rows").innerHTML=pool.map(a=>{
    const finds=(a.findings||[]).filter(f=>f.verdict==="confirmed"||f.verdict==="unverifiable");
    const inner=finds.length?finds.map(f=>
      `<div class="f"><span class="badge" style="border-color:${VC[f.verdict]};color:${VC[f.verdict]}">${VL[f.verdict]}</span>
      <span><b>${esc(f.type)}</b> · ${esc(f.severity)} · ${esc(f.matched_at||"")}<br>
      <span class="cmd">sha256 ${(f.evidence_sha256||"").slice(0,16)}</span><br>
      <span class="cmd">${esc(f.repro_command||"")}</span></span></div>`).join("")
      :`<div class="f"><span class="cmd">无已验证 finding</span></div>`;
    return `<tr><td><input type="checkbox" class="chk" value="${esc(a.key)}"></td>
      <td><b>${esc(a.target)}</b></td><td class="mono" style="font-size:11px">${a.port}/${a.protocol||"—"}</td>
      <td>${riskBadge(a.risk_level)}</td><td class="mono">${a.vuln_count||0}</td><td class="mono">${a.pending_review||0}</td>
      <td>${(a.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join("")||""}</td></tr>
      <tr class="find" hidden><td colspan="7">${inner}</td></tr>`;
  }).join("") || `<tr class="empty"><td colspan="7">无匹配资产</td></tr>`;
  $("empty").hidden=pool.length>0;
}
$("q").addEventListener("input",render);
$("rows").addEventListener("click",e=>{
  if(e.target.closest(".chk"))return;
  const tr=e.target.closest("tr");if(!tr||!tr.nextElementSibling)return;
  const find=tr.nextElementSibling;if(find.classList.contains("find"))find.hidden=!find.hidden;});
function selectedKeys(){return [...document.querySelectorAll(".chk:checked")].map(c=>c.value);}
$("ftype").addEventListener("change",()=>{
  const v=$("ftype").value; $("scanOpts").hidden=v!=="scan"; $("verifyOpts").hidden=v!=="verify";});
$("stop").addEventListener("click",async()=>{if(curJob){await api("/api/jobs/"+curJob+"/cancel",{method:"POST"});}});
$("go").addEventListener("click",runCmd);
$("nlpGo").addEventListener("click",async()=>{
  const t=$("nlpInput").value.trim();if(!t)return toast("输入指令");
  try{
    const r=await api("/api/nlp",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text:t})});
    if(r.error){log("err",r.error);return toast(r.error);}
    if(r.job_id){curJob=r.job_id;log("ac","指令 → "+r.kind+" "+r.job_id);
      $("go").disabled=true;$("stop").disabled=false;pollT=setInterval(poll,900);await poll();}
    else if(r.ok){toast(r.message||"完成");log("ok",r.message||"完成");
      if(r.stats)log("ok",`资产 ${r.stats.total_assets} · 确认漏洞 ${r.stats.total_confirmed} · 待复核 ${r.stats.pending_review}`);
      loadAssets();}
    else log("warn","未理解指令");
  }catch(e){log("err",e.message);}
});
$("ago").addEventListener("click",async()=>{
  const g=$("agoal").value.trim();if(!g)return toast("输入任务目标");
  try{
    const r=await api("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({type:"agent",goal:g})});
    curJob=r.job_id;log("ac","🧠 已交给 Claude Agent "+r.job_id);
    $("go").disabled=true;$("stop").disabled=false;pollT=setInterval(poll,900);await poll();
  }catch(e){log("err",e.message);}
});
$("exp").addEventListener("click",()=>{const a=document.createElement("a");
  a.href="/api/report?full=1&download=1";a.download="hexstrike-report.md";document.body.appendChild(a);a.click();a.remove();
  log("ok","报告已导出");});
$("clr").addEventListener("click",()=>$("log").innerHTML="");
$("bAddTag").addEventListener("click",async()=>{const ks=selectedKeys();if(!ks.length)return toast("先勾选资产");
  const t=prompt("新增标签（逗号分隔）");if(t)try{await api("/api/assets/tags",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({keys:ks,add:t.split(",")})});toast("标签已加");loadAssets();}catch(e){toast("失败："+e.message);}});
$("bDel").addEventListener("click",async()=>{const ks=selectedKeys();if(!ks.length)return toast("先勾选资产");
  if(!confirm("删除 "+ks.length+" 个资产？"))return;
  try{await api("/api/assets/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({keys:ks})});
    toast("已删除");loadAssets();}catch(e){toast("失败："+e.message);}});
$("bMerge").addEventListener("click",async()=>{const ks=selectedKeys();if(ks.length<2)return toast("勾选 2 个以上才能合并");
  try{await api("/api/assets/merge",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({keep:ks[0],keys:ks.slice(1)})});
    toast("已合并");loadAssets();}catch(e){toast("失败："+e.message);}});

async function runCmd(){
  const tgt=$("tgt").value.trim();const type=$("ftype").value;
  if($("go").disabled)return;
  const body={type};
  if(type==="scan"){body.target=tgt;if(!tgt)return toast("填目标");body.severity=$("sev").value.trim();body.tags=$("tags").value.trim();
    body.template=$("tmpl").value.trim();body.additional_args=$("extra").value.trim();}
  else{const js=$("fjs").value.trim();if(!js)return toast("填 findings JSON");body.findings_json=js;}
  $("go").disabled=true;$("stop").disabled=false;
  const j=await api("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  curJob=j.job_id;log("ac","已提交 "+j.kind+" "+j.job_id);
  pollT=setInterval(poll,900);
  await poll();
}
async function poll(){
  try{const j=await api("/api/jobs/"+curJob);
    $("log").innerHTML=j.log.join("<br>");
    $("log").scrollTop=$("log").scrollHeight;
    if(j.status==="done"){clearInterval(pollT);$("go").disabled=false;$("stop").disabled=true;
      if(j.result){log("ok","完成 — "+(j.result.total||0)+" finding，已复现 "+(j.result.confirmed||0)
         +"，未复现 "+(j.result.refuted||0)+"，待复核 "+(j.result.unverifiable||0));}
      loadAssets();curJob=null;}
    else if(j.status==="error"){clearInterval(pollT);$("go").disabled=false;$("stop").disabled=true;curJob=null;}
  }catch(e){clearInterval(pollT);$("go").disabled=false;$("stop").disabled=true;curJob=null;log("err",e.message);}
}
loadAssets();
</script>
</body></html>"""


# ---- 后台执行（jobs）----

class Job:
    def __init__(self, job_id, kind, label):
        self.job_id = job_id
        self.kind = kind
        self.label = label
        self.status = "running"   # running / done / error / cancelled
        self.log = []
        self.result = None
        self.error = ""


class _Jobs:
    def __init__(self):
        self.store = {}
        self.lock = threading.Lock()

    def create(self, kind, label):
        with self.lock:
            jid = uuid.uuid4().hex[:8]
            job = Job(jid, kind, label)
            self.store[jid] = job
        return job

    def get(self, jid):
        return self.store.get(jid)

    def render(self, job):
        return {"job_id": job.job_id, "kind": job.kind, "status": job.status,
                "log": job.log, "result": job.result, "error": job.error}


def _client():
    """惰性建 HexStrikeClient（避免循环 import：hexstrike_mcp 顶部 import dashboard）。"""
    from hexstrike_mcp import HexStrikeClient
    global _hexstrike_client
    if _hexstrike_client is None:
        _hexstrike_client = HexStrikeClient()
    return _hexstrike_client


_hexstrike_client = None
_jobs = _Jobs()


def _ts():
    return __import__("datetime").datetime.now().strftime("%H:%M:%S")


def _run_agent_job(job, params):
    """把目标交给 Claude agent（headless `claude -p`）复用现有 agent 框架。

    `claude -p` 加载同一套 hexstrike MCP 工具（user scope），自我规划、调用
    工具、写快照，与当前会话同一模型链路。事件流经 stream-json 转成前端日志。
    """
    import shlex
    goal = (params.get("goal") or "").strip()
    if not goal:
        job.status = "error"
        job.error = "goal 为空"
        return
    try:
        s = _snapshot_db.stats()
        prompt = (goal + "\n\n（当前资产快照：%d 资产 · 确认漏洞 %d · 待复核 %d。"
                  "需要时可调 snapshot_report / query_assets 看上下文；若有新增或变更，"
                  "完成后调 snapshot_update 写回快照。最后用中文简洁总结。）"
                  % (s["total_assets"], s["total_confirmed"], s["pending_review"]))
    except Exception:
        prompt = goal
    cmd = ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
           "--allowedTools", "mcp__hexstrike-ai__*"]
    cwd = os.path.dirname(os.path.abspath(__file__))
    job.log.append(f'<span class="t">{_ts()}</span> <span class="ac">🧠 交给 Claude Agent（headless）· {goal[:60]}</span>')
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, env=dict(os.environ))
        for line in proc.stdout or []:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            msg = ev.get("message") or {}
            for c in msg.get("content") or []:
                t = c.get("type")
                if t == "text" and c.get("text"):
                    job.log.append(f'<span class="t">{_ts()}</span> <span class="ok">{c["text"]}</span>')
                elif t == "tool_use":
                    name = c.get("name", "")
                    job.log.append(f'<span class="t">{_ts()}</span> <span class="ac">⚙ {name}</span>')
                    inp = c.get("input") or {}
                    key = next((k for k in ("target", "findings_json", "query", "goal")
                                if str(k) in inp), None)
                    val = inp.get(key, "") if key else ""
                    if name.startswith("mcp__hexstrike-ai__") and str(val):
                        job.log.append(f'<span class="t">{_ts()}</span> <span class="cmd">'
                                       f'&nbsp;&nbsp;↳ {str(val)[:110]}</span>')
        rc = proc.wait()
        job.result = {"rc": rc, "note": "agent 执行完毕"}
        job.status = "done"
    except Exception as e:
        job.status = "error"
        job.error = str(e)
        job.log.append(f'<span class="t">{_ts()}</span> <span class="err">✖ {e}</span>')


def _run_job(job, params):
    if job.kind == "agent":
        return _run_agent_job(job, params)
    from verifiers import nuclei_scan_and_verify, verify_findings
    try:
        logln = lambda s: job.log.append(f'<span class="t">{_ts()}</span> {s}')
        client = _client()
        if job.kind == "scan":
            logln('▶ <span class="ac">nuclei -jsonl 扫描 + 独立复验</span> ' + params.get("target", ""))
            res = nuclei_scan_and_verify(client, params.get("target", ""),
                                         severity=params.get("severity", ""),
                                         tags=params.get("tags", ""),
                                         template=params.get("template", ""),
                                         additional_args=params.get("additional_args", ""))
            scan = res.get("scan") or {}
            n = scan.get("converted_findings", 0)
            logln(f"nuclei 命中 {n} 条 → 独立复验（curl/nc/openssl）完成")
            job.result = res
        else:
            fjs = params.get("findings_json", "")
            logln("▶ 独立验证 findings（curl/nc/openssl）")
            res = verify_findings(client, fjs, only_types=params.get("only_types", ""))
            logln(f"验证完成：confirmed {res['confirmed']} / refuted {res['refuted']} / unverifiable {res['unverifiable']}")
            job.result = res
        # 自动写资产快照
        try:
            added = _snapshot_db.record_verifications(job.result.get("results", []))
            logln(f"√ 写入资产快照：新增 {added['assets_created']} / 更新 {added['assets_updated']}")
        except Exception as e:
            logln(f"! 快照写入失败：{e}")
        job.status = "done"
    except Exception as e:
        job.status = "error"
        job.error = str(e)
        job.log.append(f'<span class="t">{_ts()}</span> <span class="err">✖ {e}</span>')


def _start_job(job, params):
    t = threading.Thread(target=_run_job, args=(job, params), daemon=True)
    t.start()
    return job


def _resolve_keys(hay: str) -> list:
    """把指令/目标词解析为快照资产 key：target 整词出现优先，再退 host。"""
    hay = hay or ""
    out = []
    for k, a in _snapshot_db.data["assets"].items():
        tgt = str(a.get("target") or "")
        host = str(a.get("host") or "")
        if tgt and re.search(r"(?<![A-Za-z0-9-])" + re.escape(tgt) + r"(?![A-Za-z0-9-])", hay):
            out.append(k)
        elif host and host in hay.split():
            out.append(k)
    return out


def _findings_from_snapshot(keys: list) -> str:
    """从快照取目标资产的 confirmed/unverifiable finding 构造成 verify 输入。"""
    res = []
    for k in keys or []:
        a = _snapshot_db.data["assets"].get(k) or {}
        for f in a.get("findings", []):
            if f.get("verdict") in ("confirmed", "unverifiable"):
                res.append({"id": f.get("id", ""), "target": a.get("target", ""),
                            "type": f.get("type", ""), "source_tool": "snapshot",
                            "matched_at": f.get("matched_at", a.get("target", "")),
                            "severity": f.get("severity", "info"), "raw": ""})
    return json.dumps(res, ensure_ascii=False)


# ---- HTTP ----

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urllib.parse.urlparse(self.path).path
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if route in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif route == "/api/stats":
            self._json(_snapshot_db.stats())
        elif route == "/api/assets":
            self._json(list(_snapshot_db.data["assets"].values()))
        elif route == "/api/report":
            full = "full=1" in q.get("full", [])
            snap = memory.AssetSnapshot(_snapshot_db.path).load()
            body = snap.to_markdown(overview_only=not full)
            if q.get("download"):
                import urllib.parse as _u
                body2 = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="hexstrike-report.md"')
                self.send_header("Content-Length", str(len(body2)))
                self.end_headers()
                self.wfile.write(body2)
                return
            self._json({"report": body, "stats": _snapshot_db.stats()})
        elif route.startswith("/api/jobs/"):
            jid = route.split("/")[-1]
            job = _jobs.get(jid)
            if job is None:
                self._json({"error": "job not found"}, 404)
            else:
                self._json(_jobs.render(job))
        else:
            self.send_error(404)

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(ln).decode("utf-8") or "{}") if ln else {}
        except json.JSONDecodeError:
            return self._json({"error": "请求体不是合法 JSON"}, 400)
        if route == "/api/jobs":
            kind = body.get("type", "scan")
            job = _jobs.create(kind, kind)
            _start_job(job, body)
            self._json(_jobs.render(job), 202)
        elif route.endswith("/cancel"):
            jid = route.split("/")[-2]
            job = _jobs.get(jid)
            if job and job.status == "running":
                job.status = "cancelled"
                job.log.append(f'<span class="t">{_ts()}</span> <span class="hot">◼ 已请求停止（后台进程由超时兜底）</span>')
            self._json({"status": job.status if job else "not_found"})
        elif route == "/api/assets/tags":
            keys = body.get("keys", []); add = body.get("add", [])
            n = 0
            for k in keys:
                a = _snapshot_db.data["assets"].get(k)
                if a:
                    a["tags"] = memory._clean_tags(a.get("tags", []) + list(add))
                    n += 1
            _snapshot_db.save()
            self._json({"updated": n})
        elif route == "/api/assets/delete":
            keys = body.get("keys", []); n = 0
            for k in keys:
                if _snapshot_db.data["assets"].pop(k, None):
                    n += 1
            _snapshot_db.save()
            self._json({"deleted": n})
        elif route == "/api/assets/merge":
            keep = body.get("keep"); keys = body.get("keys", [])
            target = _snapshot_db.data["assets"].get(keep)
            if not target:
                return self._json({"error": "主资产不存在"}, 404)
            for k in keys:
                other = _snapshot_db.data["assets"].pop(k, None)
                if not other:
                    continue
                target["tags"] = memory._clean_tags(target.get("tags", []) + other.get("tags", []))
                for f in other.get("findings", []):
                    if f not in target.setdefault("findings", []):
                        target["findings"].append(f)
            _snapshot_db._recompute_risk(target)
            _snapshot_db.save()
            self._json({"merged": len(keys)})
        elif route == "/api/nlp":
            from nlp import parse_action
            text = str(body.get("text") or "").strip()
            if not text:
                return self._json({"error": "指令为空"}, 400)
            action = parse_action(text)
            op = action.get("op")
            p = action.get("params") or {}

            if op in ("scan", "verify"):
                if op == "scan":
                    if not p.get("target"):
                        return self._json({"error": "未能从指令提取目标（示例：扫描 https://host 的高危 xss）"}, 400)
                else:
                    fjs = (p.get("findings_json") or "").strip()
                    if not fjs:
                        keys = _resolve_keys(text + " " + p.get("target", ""))
                        fjs = _findings_from_snapshot(keys)
                        if not fjs or fjs == "[]":
                            return self._json({"error": "该目标快照里没有可复验 finding，可在指令中直接贴 findings JSON"}, 400)
                    p["findings_json"] = fjs
                job = _jobs.create(op, op)
                _start_job(job, p)
                self._json(_jobs.render(job), 202)
            elif op == "tag":
                keys = _resolve_keys(text + " " + p.get("target", ""))
                add = [t.strip() for t in re.split(r"[,，;；\s]+", p.get("add") or "") if t.strip()]
                if not keys:
                    return self._json({"error": "快照里没匹配到目标资产"}, 404)
                if not add:
                    return self._json({"error": "没看懂要加什么标签"}, 400)
                n = 0
                for k in keys:
                    a = _snapshot_db.data["assets"].get(k)
                    if a:
                        a["tags"] = memory._clean_tags(a.get("tags", []) + add)
                        n += 1
                _snapshot_db.save()
                self._json({"ok": True, "message": f"已给 {n} 个资产加标签：{','.join(add)}", "matched": keys})
            elif op == "delete":
                keys = _resolve_keys(text + " " + p.get("target", ""))
                if not keys:
                    return self._json({"error": "快照里没匹配到目标资产"}, 404)
                n = sum(1 for k in keys if _snapshot_db.data["assets"].pop(k, None))
                _snapshot_db.save()
                self._json({"ok": True, "message": f"已删除 {n} 个资产", "matched": keys})
            elif op == "merge":
                keys = _resolve_keys(text + " " + (p.get("keep") or ""))
                if len(keys) < 2:
                    return self._json({"error": "合并需要至少匹配到 2 个资产"}, 400)
                keep = keys[0]
                target = _snapshot_db.data["assets"].get(keep)
                merged = 0
                for k in keys[1:]:
                    other = _snapshot_db.data["assets"].pop(k, None)
                    if not other:
                        continue
                    target["tags"] = memory._clean_tags(target.get("tags", []) + other.get("tags", []))
                    for f in other.get("findings", []):
                        if f not in target.setdefault("findings", []):
                            target["findings"].append(f)
                    merged += 1
                _snapshot_db._recompute_risk(target)
                _snapshot_db.save()
                self._json({"ok": True, "message": f"已合并 {merged} 个资产到 {target.get('target', keep)}"})
            elif op == "report":
                md = _snapshot_db.to_markdown(overview_only=False)
                self._json({"ok": True, "report_note": "报告已生成", "report": md,
                            "stats": _snapshot_db.stats()})
            else:
                self._json({"ok": True, "stats": _snapshot_db.stats()})
        else:
            self._json({"error": "unknown route"}, 404)

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send(self, code, body, ctype):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class _DashHTTPD(ThreadingHTTPServer):
    daemon_threads = True


class Dash:
    def __init__(self, snapshot_path="", host="127.0.0.1", port=DEFAULT_PORT):
        global _snapshot_db
        self.host = host
        self.port = int(port)
        _snapshot_db = memory.AssetSnapshot(snapshot_path).load()
        self._httpd = None

    def start(self):
        if self._httpd:
            return self
        self._httpd = _DashHTTPD((self.host, self.port), _Handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def url(self):
        return f"http://{self.host}:{self.port}/"

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


_snapshot_db = None
_active = {}


def start_dashboard(snapshot_path: str = "", port: int = DEFAULT_PORT,
                    host: str = "127.0.0.1", open_browser: bool = True) -> dict:
    """启动（或复用）本地 Web 控制台并可选打开浏览器。"""
    key = (host, int(port))
    dash = _active.get(key)
    created = dash is None
    if dash is None:
        dash = Dash(snapshot_path, host, port).start()
        _active[key] = dash
    url = dash.url()
    if open_browser:
        webbrowser.open(url)
    return {"url": url, "port": int(port), "status": "running",
            "created": created, "snapshot": _snapshot_db.stats()}


def stop_dashboard(port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> dict:
    with _active_lock:
        dash = _active.pop((host, int(port)), None)
    if dash:
        dash.stop()
        return {"status": "stopped", "port": int(port)}
    return {"status": "not_running", "port": int(port)}


_active_lock = threading.Lock()


if __name__ == "__main__":
    import sys
    print(start_dashboard(sys.argv[1] if len(sys.argv) > 1 else ""))
    import time
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_dashboard()