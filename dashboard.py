#!/usr/bin/env python3
"""HexStrike Web 控制台（改造④-交互）—— 本地可视化 + 可执行操作的交互 Web。

零第三方依赖（标准库 http.server + webbrowser）。把 HexStrike 能力搬上网页：
- 发起扫描（nuclei -jsonl → 自动验证）、校验 findings、写资产快照
- 资产增删改/合并/标签、报告导出、活动日志（mono 事件流）
数据来自 memory.AssetSnapshot；执行复用 verifiers / hexstrike_mcp.HexStrikeClient。
界面风格：审计作战室 ——「界面即命令」，动作即可复现命令事件行。
仅绑 127.0.0.1；扫描/验证会对目标真实发请求。
"""

import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
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
#skillMenu{position:fixed;z-index:20;min-width:240px;max-width:340px;max-height:300px;overflow:auto;
  background:var(--surface,#181a1f);border:1px solid var(--line,#2a2d33);border-radius:8px;
  box-shadow:0 8px 28px rgba(0,0,0,.45);font-size:12.5px;color:var(--ink,#e6e8ec)}
#skillMenu .sm{padding:6px 10px;cursor:pointer;border-bottom:1px solid var(--line,#202328);display:flex;flex-wrap:wrap;gap:2px 8px;align-items:baseline}
#skillMenu .sm .smn{font-size:12.5px;flex:1 1 auto}
#skillMenu .sm .sms{margin-left:auto;color:var(--ink3,#7a7e87);font-size:10px;font-family:var(--mono);text-transform:uppercase}
#skillMenu .sm .smd{flex-basis:100%;font-size:10.5px;color:var(--ink3,#7a7e87);line-height:1.35;margin-top:1px}
#skillMenu .sm:hover{background:var(--acc,#4e7dff);color:#fff}
#skillMenu .sm.sel{background:var(--acc,#4e7dff);color:#fff}
#skillMenu .smh{padding:4px 10px;font-size:10px;color:var(--ink3,#7a7e87);text-transform:uppercase;
  letter-spacing:.4px;background:var(--surface2,#202328);border-bottom:1px solid var(--line,#202328);position:sticky;top:0}
#uxModal{position:fixed;inset:0;z-index:21;background:rgba(0,0,0,.55);align-items:flex-start;justify-content:center;padding:40px 16px}
#uxModal[hidden]{display:none!important}
#uxModal:not([hidden]){display:flex}
.uxm{width:min(760px,94vw);max-height:80vh;display:flex;flex-direction:column;background:var(--surface,#181a1f);
  border:1px solid var(--line,#2a2d33);border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.5)}
.uxh{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line,#202328)}
.uxb{padding:12px 14px;overflow:auto}
.uxrow{display:flex;gap:10px;padding:8px 10px;border-bottom:1px solid var(--line,#202328);cursor:pointer;align-items:flex-start}
.uxrow:hover{background:var(--surface2,#202328)}
.uxrow .px{font-family:var(--mono);font-size:10.5px;color:var(--ink3,#7a7e87);word-break:break-all;margin-top:2px}
.uxpre{white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:11.5px;background:var(--surface2,#202328);
  padding:10px;border-radius:6px;max-height:380px;overflow:auto}
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
      <input id="agoal" placeholder="对 https://example.com 做侦查… 或 /neat-freak 整理文档；可加 --model opus">
      <button class="btn ghost" id="ago" style="flex:none">🧠 Agent 执行</button>
    </div>
    <div class="hint">整段 = claude 命令行：支持 /技能名、--model/--max-turns 等 flag、其余为 prompt。类别词：/skills /mcp /tools /plugin /cmd（/mcp 显示服务器）</div>
    <label id="auseWrap" style="display:flex;gap:10px;align-items:center;margin-top:8px;padding:9px 11px;border:1px solid var(--line);border-radius:6px;cursor:pointer;user-select:none;background:var(--surface)">
      <input type="checkbox" id="ause" style="width:16px;height:16px;accent-color:var(--acc);flex:none">
      <span style="font-size:12.5px;color:var(--ink);line-height:1.45">接着上一个任务继续
        <span style="display:block;color:var(--ink2);font-size:11px;line-height:1.4">不勾＝从零开新会话（只读快照兜底）；勾上＝追加到最近一次 agent 会话，记得此前全部步骤</span>
      </span>
    </label>
    <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
      <label for="amodel" style="flex:none;margin:0">模型</label>
      <select id="amodel">
        <option value="">默认</option>
        <option value="opus">opus（最强）</option>
        <option value="sonnet">sonnet（均衡）</option>
        <option value="haiku">haiku（快）</option>
      </select>
      <label style="display:flex;gap:6px;align-items:center;margin:0;cursor:pointer">
        <input type="checkbox" id="afence" style="width:15px;height:15px;accent-color:var(--acc)">
        <span style="font-size:12px">工具白名单</span>
      </label>
    </div>
    <input id="atools" placeholder="逗号分隔，如 Bash,Read,Write,mcp__hexstrike-ai__query_assets" disabled style="margin-top:6px">
    <div class="hint">勾选工具白名单 → 注入 --allowedTools（名单外工具拒绝，拒绝记录进日志）</div>
    <div id="agentCtl" style="display:none;gap:8px;margin-top:8px;align-items:center">
      <button class="btn ghost" id="aint" style="flex:none">⏸ 中断</button>
      <input id="aadj" placeholder="调整指令（留空＝继续）" style="flex:1;min-width:0">
      <button class="btn ghost" id="ares" style="flex:none">▶ 继续</button>
    </div>
    <hr style="border:none;border-top:1px solid var(--line);margin:14px 0 2px">
    <label for="tgt">目标（URL / 域名 / IP）</label>
    <input id="tgt" placeholder="https://host / host:port" value="">
    <div class="opts">
      <label for="ftype">扫描类型</label>
      <select id="ftype">
        <option value="scan">扫描并验证（nuclei → 自动复验）</option>
        <option value="verify">仅独立验证 findings（JSON）</option>
      </select>
    </div>
    <div id="scanOpts">
      <button type="button" class="btn ghost small" id="advTgl" style="margin:6px 0">高级选项 ▸</button>
      <div id="advOpts" hidden>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          <div><label for="sev">severity</label><input id="sev" placeholder="high,medium" value=""></div>
          <div><label for="tags">tags</label><input id="tags" placeholder="xss,sqli" value=""></div>
        </div>
        <label for="tmpl">template（-t，可选）</label><input id="tmpl" placeholder="/path/template.yaml">
        <label for="extra">additional args</label><input id="extra" placeholder="-rl 20">
      </div>
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
<div id="skillMenu" hidden></div>
<div id="uxModal" hidden><div class="uxm">
  <div class="uxh"><b id="uxTitle">面板</b><button class="btn ghost small" id="uxClose">✕</button></div>
  <div class="uxb" id="uxBody"></div>
</div></div>

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
function setBusy(b){$("go").disabled=b;$("ago").disabled=b;$("nlpGo").disabled=b;$("stop").disabled=!b;}
function startPoll(){clearInterval(pollT);pollT=setInterval(poll,900);}
function jobHead(j){return `<div class="ln"><span class="t">▶ 当前任务</span>
  <span class="${j.kind==="agent"?"ac":"ok"}">${esc(j.kind)} ${esc(j.job_id)} · ${esc(j.status)}</span>
  ${j.session_id?`<span class="cmd">会话 ${esc(j.session_id)}</span>`:""}</div>`;}
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
  }).join("") || `<tr class="empty"><td colspan="7">${assets.length?"无匹配资产":"快照为空 — 先发起一次操作"}</td></tr>`;
}
$("q").addEventListener("input",render);
$("rows").addEventListener("click",e=>{
  if(e.target.closest(".chk"))return;
  const tr=e.target.closest("tr");if(!tr||!tr.nextElementSibling)return;
  const find=tr.nextElementSibling;if(find.classList.contains("find"))find.hidden=!find.hidden;});
function selectedKeys(){return [...document.querySelectorAll(".chk:checked")].map(c=>c.value);}
$("ftype").addEventListener("change",()=>{
  const v=$("ftype").value; $("scanOpts").hidden=v!=="scan"; $("verifyOpts").hidden=v!=="verify";});
$("advTgl").addEventListener("click",()=>{const o=$("advOpts"),b=$("advTgl");
  o.hidden=!o.hidden;b.textContent=o.hidden?"高级选项 ▸":"高级选项 ▾";});
$("stop").addEventListener("click",async()=>{if(curJob){await api("/api/jobs/"+curJob+"/cancel",{method:"POST"});}});
$("go").addEventListener("click",runCmd);
$("nlpGo").addEventListener("click",async()=>{
  const t=$("nlpInput").value.trim();if(!t)return toast("输入指令");
  if($("go").disabled)return toast("上一个任务还在跑，先完成或停止它");
  try{
    const r=await api("/api/nlp",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text:t})});
    if(r.error){log("err",r.error);return toast(r.error);}
    if(r.job_id){curJob=r.job_id;log("ac","指令 → "+r.kind+" "+r.job_id);
      setBusy(true);startPoll();await poll();}
    else if(r.ok){toast(r.message||"完成");log("ok",r.message||"完成");
      if(r.stats)log("ok",`资产 ${r.stats.total_assets} · 确认漏洞 ${r.stats.total_confirmed} · 待复核 ${r.stats.pending_review}`);
      loadAssets();}
    else log("warn","未理解指令");
  }catch(e){log("err",e.message);}
});
$("ago").addEventListener("click",async()=>{
  const g=$("agoal").value.trim();if(!g)return toast("输入任务目标");
  if($("go").disabled)return toast("上一个任务还在跑，先完成或停止它");
  try{
    const r=await api("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({type:"agent",goal:g,resume_session:$("ause").checked?"last":"",
        model:agentModel(),fence:agentFence()})});
    if(r.error)return toast(r.error);
    curJob=r.job_id;log("ac","🧠 已交给 Claude Agent "+r.job_id+($("ause").checked?"（续上一会话）":""));
    setBusy(true);startPoll();await poll();
  }catch(e){log("err",e.message);}
});
function agentModel(){return $("amodel").value;}
function agentFence(){return $("afence").checked?($("atools").value||"").trim():"";}
$("afence").addEventListener("change",()=>{$("atools").disabled=!$("afence").checked;});
$("aint").addEventListener("click",async()=>{if(!curJob)return;
  try{await api("/api/jobs/"+curJob+"/interrupt",{method:"POST"});toast("已中断，可输入调整后继续");}
  catch(e){toast("失败："+e.message);}});
$("ares").addEventListener("click",async()=>{if(!curJob)return;
  const text=$("aadj").value.trim();
  try{await api("/api/jobs/"+curJob+"/resume",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({text,model:agentModel(),fence:agentFence()})});$("aadj").value="";toast("已继续");}
  catch(e){toast("失败："+e.message);}});
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
  setBusy(true);
  const j=await api("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  curJob=j.job_id;log("ac","已提交 "+j.kind+" "+j.job_id);
  startPoll();
  await poll();
}
async function poll(){
  try{const j=await api("/api/jobs/"+curJob);
    $("log").innerHTML=jobHead(j)+j.log.join("<br>");
    $("log").scrollTop=$("log").scrollHeight;
    updateAgentCtl(j);
    if(j.status==="done"){clearInterval(pollT);pollT=null;setBusy(false);
      updateAgentCtl(j);
      if(j.result){log("ok","完成 — "+(j.result.total||0)+" finding，已复现 "+(j.result.confirmed||0)
         +"，未复现 "+(j.result.refuted||0)+"，待复核 "+(j.result.unverifiable||0));}
      loadAssets();curJob=null;}
    else if(j.status==="error"||j.status==="cancelled"){clearInterval(pollT);pollT=null;setBusy(false);curJob=null;}
  }catch(e){clearInterval(pollT);pollT=null;setBusy(false);
    $("agentCtl").style.display="none";curJob=null;log("err",e.message);}
}
function updateAgentCtl(j){
  const ctl=$("agentCtl");
  if(j.kind==="agent"){ctl.style.display="flex";
    $("aint").disabled=j.status!=="running";$("ares").disabled=j.status!=="paused";}
  else ctl.style.display="none";
}
let MENU=[],skillCtx=null;
async function loadMenu(){try{const r=await api("/api/menu");MENU=r.items||[];}catch(e){}}
function tokSplit(v){const sp=v.lastIndexOf(" ");return [v.slice(0,sp+1),v.slice(sp+1)];}
function skillMenuHide(){const m=$("skillMenu");m.hidden=true;skillCtx=null;}
function attachSkill(id){const el=$(id);
  el.addEventListener("input",()=>{const [pre,tok]=tokSplit(el.value);
    tok.startsWith("/")?skillMenuShow(el,pre,tok.slice(1)):skillMenuHide();});
  el.addEventListener("blur",()=>setTimeout(skillMenuHide,180));
  el.addEventListener("keydown",e=>{
    if($("skillMenu").hidden)return;
    if(e.key==="Enter"){const s=$("skillMenu").querySelector(".sel");if(s){e.preventDefault();skillPick(s);}}
    else if(e.key==="Escape"){e.preventDefault();skillMenuHide();}
    else if(e.key==="ArrowDown"||e.key==="ArrowUp"){e.preventDefault();skillNav(e.key==="ArrowDown"?1:-1);}
  });
}
function skillRow(it){
  const badge=it.kind==="mcp"?"mcp":(it.kind==="mcp-server"?"server":(it.source||""));
  const label=it.kind==="mcp-server"?"mcp__"+it.name+"__":it.label;
  const d=it.desc?`<span class="smd">${esc(it.desc)}</span>`:"";
  return `<div class="sm" data-kind="${it.kind}" data-name="${esc(it.name)}"><span class="smn">${esc(label)}</span><span class="sms">${esc(badge)}</span>${d}</div>`;
}
const CAT_KEYS={skill:"skill",skills:"skill",技能:"skill",
  mcp:"mcp",plugin:"plugin",plugins:"plugin",插件:"plugin",
  cmd:"cmd",command:"cmd",commands:"cmd",命令:"cmd",
  tools:"tools",tool:"tools",工具:"tools"};
function skillMenuShow(el,pre,q){
  const ql=q.toLowerCase();
  const m=$("skillMenu");
  const cat=CAT_KEYS[ql];
  const skillAll=MENU.filter(it=>it.kind==="skill");
  let rows;
  if(cat==="skill"){
    rows=[["技能清单",skillAll,80]];
  }else if(cat==="mcp"){
    // TUI 语义：/mcp 显示的是 MCP 服务器（会话连接），不是单个工具
    const servers=[{name:"hexstrike-ai",kind:"mcp-server",label:"hexstrike-ai"}]
      .concat(MENU.filter(it=>it.kind==="mcp-server"));
    rows=[["MCP 服务器（会话内连接）",servers,10]];
  }else if(cat==="tools"){
    rows=[["MCP 工具（mcp__hexstrike-ai__）",MENU.filter(it=>it.kind==="mcp"),80]];
  }else if(cat==="plugin"){
    rows=[["插件技能",skillAll.filter(s=>s.source==="plugin"),60],
          ["其它技能",skillAll.filter(s=>s.source!=="plugin"),20]];
  }else if(cat==="cmd"){
    rows=[["命令",MENU.filter(it=>it.kind==="cmd"),30]];
  }else if(ql===""){
    rows=[["技能 / 插件",skillAll,40],["命令",MENU.filter(it=>it.kind==="cmd"),12]];
  }else{
    const hits=MENU.filter(it=>it.kind!=="mcp-server"&&it.kind!=="mcp" &&
      (it.name+" "+it.label).toLowerCase().includes(ql));
    rows=[["命令",hits.filter(it=>it.kind==="cmd"),12],
          ["技能 / 插件",hits.filter(it=>it.kind==="skill"),20]];
  }
  let html="",total=0;
  for(const [title,list,cap] of rows){
    if(!list.length)continue;
    html+=`<div class="smh">${title}（${list.length}）</div>`;
    html+=list.slice(0,cap).map(skillRow).join("");
    total+=Math.min(list.length,cap);
    if(list.length>cap)html+=`<div class="smh" style="text-transform:none">… 还有 ${list.length-cap} 个</div>`;
  }
  if(!total){m.hidden=true;skillCtx=null;return;}
  m.innerHTML=html;
  skillCtx={el,pre};
  const first=m.querySelector(".sm"); if(first)first.classList.add("sel");
  const r=el.getBoundingClientRect();
  m.style.left=Math.min(r.left,window.innerWidth-420)+"px";
  m.style.top=Math.min(r.bottom+4,window.innerHeight-320)+"px";
  m.hidden=false;
  m.querySelectorAll(".sm").forEach(d=>{
    d.addEventListener("mousedown",ev=>{ev.preventDefault();skillPick(d);});
    d.addEventListener("mouseover",()=>{m.querySelectorAll(".sm").forEach(x=>x.classList.remove("sel"));d.classList.add("sel");});
  });
}
function skillNav(d){
  const items=[...$("skillMenu").querySelectorAll(".sm")];
  const i=items.findIndex(x=>x.classList.contains("sel"));
  if(i<0)return;
  items[i].classList.remove("sel");
  const j=(i+d+items.length)%items.length;
  items[j].classList.add("sel");items[j].scrollIntoView({block:"nearest"});
}
function skillPick(d){
  const ctx=skillCtx;if(!ctx)return;
  const k=d.dataset.kind,name=d.dataset.name;
  if(k==="cmd"){skillMenuHide();openPanel(name);return;}
  const insert=k==="mcp"?"mcp__hexstrike-ai__"+name+" "
              :k==="mcp-server"?"mcp__"+name+"__"
              :"/"+name+" ";
  const v=ctx.pre+insert;
  ctx.el.value=v;ctx.el.focus();ctx.el.setSelectionRange(v.length,v.length);
  skillMenuHide();
}
function renderMcp(){
  const b=$("uxBody");
  api("/api/mcp").then(r=>{
    b.innerHTML=`<div class="hint" style="margin:0 0 8px">会话级开关：控制「控制台发起的 agent」连哪些服务器（不影响当前 Claude 会话）。hexstrike-ai 为平台必需。</div>`
      + r.servers.map(s=>{
        const tgl=s.locked
          ? `<span class="badge" style="color:#0ca30c;border-color:#0ca30c">必需</span>`
          : `<button class="btn ghost small" data-tgl="${esc(s.name)}" data-on="${s.enabled}">${s.enabled?"● 已启用":"○ 已停用"}</button>`;
        return `<div class="uxrow" style="cursor:default"><div style="flex:1"><b>${esc(s.name)}</b>
          <div class="px">${esc(s.type||"")} · ${esc(s.command||"")} ${esc(s.args||"")}</div></div>
          <span class="mono" style="font-size:11px">${s.tools?s.tools+" 工具":""}</span>${tgl}</div>`;
      }).join("");
    b.querySelectorAll("button[data-tgl]").forEach(bt=>bt.addEventListener("click",ev=>{
      ev.stopPropagation();
      api("/api/mcp/toggle",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({name:bt.dataset.tgl,enabled:bt.dataset.on!=="true"})})
        .then(renderMcp).catch(err=>toast(err.message));
    }));
  }).catch(e=>b.innerHTML="<div class='err'>"+esc(e.message)+"</div>");
}
function openPanel(kind){
  const m=$("uxModal"),b=$("uxBody");
  b.innerHTML='<div class="cmd" style="text-align:center;padding:20px">载入中…</div>';m.hidden=false;
  if(kind==="mcp"){ $("uxTitle").textContent="MCP 服务器"; renderMcp(); return; }
  if(kind==="skills"){ $("uxTitle").textContent="技能"; renderSkillsPanel(); return; }
  api("/api/panel/"+kind).then(renderPanel).catch(e=>b.innerHTML="<div class='err'>"+esc(e.message)+"</div>");
}
function renderSkillsPanel(){
  const b=$("uxBody");
  api("/api/skills").then(r=>{
    b.innerHTML=r.skills.map(s=>{
      const act=s.path
        ? `<span class="cmd" style="flex:none;color:var(--acc,#4e7dff)">查看 ▸</span>`
        : `<span class="cmd" style="flex:none;color:var(--ink3,#7a7e87)">内置（无文件）</span>`;
      return `<div class="uxrow" data-skill="${esc(s.name)}" data-path="${esc(s.path)}">
      <div style="flex:1"><b>${esc(s.name)}</b> <span class="sms">${esc(s.source)}</span>
      ${s.desc?`<div class="cmd" style="font-size:11.5px;color:var(--ink2)">${esc(s.desc)}</div>`:""}
      <div class="px">${esc(s.path)}</div></div>${act}</div>`;
    }).join("")
      + "<div id='uxpreview'></div>";
    b.querySelectorAll(".uxrow").forEach(d=>{if(d.dataset.path)d.addEventListener("click",()=>previewSkill(d.dataset.skill));});
  }).catch(e=>b.innerHTML="<div class='err'>"+esc(e.message)+"</div>");
}
function renderPanel(r){
  const b=$("uxBody");
  $("uxTitle").textContent=r.title||"面板";
  if(r.kind==="model"){
    b.innerHTML=r.options.map(o=>{
      const cur=o.name===$("amodel").value?"<span class='sms'>当前</span>":"";
      return `<div class="uxrow" data-model="${esc(o.name)}"><div style="flex:1"><b>${esc(o.name||"默认")}</b> ${cur}<div class="px">${esc(o.desc)}</div></div></div>`;
    }).join("");
    b.querySelectorAll(".uxrow").forEach(d=>d.addEventListener("click",()=>{$("amodel").value=d.dataset.model;toast("已选模型 "+(d.dataset.model||"默认"));renderPanel(r);}));
    return;
  }
  if(r.kind==="action"){
    let extra="";
    if(r.action==="clear")extra=`<button class="btn ghost small" id="pact">重开新会话（不续上一会话）</button>`;
    else if(r.action==="resume")extra=`<button class="btn ghost small" id="pact">勾选「🔗 续上一会话」</button>`;
    b.innerHTML=`<div class="uxrow" style="cursor:default"><div style="flex:1">${esc(r.desc)}</div></div><div style="margin-top:10px">${extra}</div>`;
    const bt=$("pact");
    if(bt)bt.addEventListener("click",()=>{
      if(r.action==="clear")$("ause").checked=false;
      else if(r.action==="resume")$("ause").checked=true;
      toast("已执行");$("uxModal").hidden=true;
    });
    return;
  }
  b.innerHTML=(r.hint?`<div class="hint" style="margin:0 0 8px">${esc(r.hint)}</div>`:"")
    + ((r.items||[]).map(it=>`<div class="uxrow" style="cursor:default"><div style="flex:1"><b>${esc(it.name)}</b>${it.desc?`<div class="px">${esc(it.desc)}</div>`:""}</div></div>`).join("")
       || "<div class='cmd'>无内容</div>");
}
function previewSkill(name){
  const p=$("uxpreview");p.textContent="载入中…";
  api("/api/skill/read?name="+encodeURIComponent(name)).then(r=>{
    p.innerHTML=`<div class="px">${esc(r.path)}</div><pre class="uxpre">${esc(r.content)}</pre>`;
  }).catch(e=>{p.innerHTML="<div class='err'>读取失败："+esc(e.message)+"</div>";});
}
$("uxClose").addEventListener("click",()=>{$("uxModal").hidden=true;});
$("uxModal").addEventListener("click",e=>{if(e.target===$("uxModal"))$("uxModal").hidden=true;});
document.addEventListener("keydown",e=>{if(e.key==="Escape"){$("skillMenu").hidden=true;$("uxModal").hidden=true;}});
loadMenu();
["agoal","aadj","nlpInput"].forEach(attachSkill);
loadAssets();
</script>
</body></html>"""


# ---- 后台执行（jobs）----

class Job:
    def __init__(self, job_id, kind, label):
        self.job_id = job_id
        self.kind = kind
        self.label = label
        self.status = "running"   # running / paused / done / error / cancelled
        self.log = []
        self.result = None
        self.error = ""
        self.session_id = ""      # agent：claude 会话 id（首跑 --session-id，续跑 --resume）
        self.proc = None          # agent：当前 claude 子进程（可中断）


class _Jobs:
    def __init__(self):
        self.store = {}
        self.lock = threading.Lock()
        self.last_agent = None       # 最近一次 agent job（供「续上一会话」）

    def create(self, kind, label):
        with self.lock:
            jid = uuid.uuid4().hex[:8]
            job = Job(jid, kind, label)
            self.store[jid] = job
        return job

    def get(self, jid):
        return self.store.get(jid)

    def active_job(self):
        """单任务模型：任一 running/paused 的 job 都算活动任务，阻塞新任务。"""
        for j in self.store.values():
            if j.status in ("running", "paused"):
                return j
        return None

    def render(self, job):
        return {"job_id": job.job_id, "kind": job.kind, "status": job.status,
                "log": job.log, "result": job.result, "error": job.error,
                "session_id": job.session_id,
                "resumable": bool(job.kind == "agent" and job.session_id)}


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


# ---- 自主任务：把输入框当 claude 命令行 + /技能 预处理器 ----

# 取值型 flag：它的下一个 token 是值（也支持 --flag=val 一体形式）
_AGENT_VALUE_FLAGS = {
    "--model", "--mode", "--append-system-prompt", "--append-system-prompt-file",
    "--system-prompt", "--system-prompt-file", "--add-dir", "--allowedTools",
    "--allowed-tools", "--disallowedTools", "--disallowed-tools", "--mcp-config",
    "--settings", "--agents", "--plugin-dir", "--permission-mode", "--max-turns",
    "--timeout-ms", "--output-format", "--fallback-model", "--input-format",
    "--add-cwd", "--expert", "--provider", "--env", "--api-key-helper", "--fallback",
}


def _split_agent_flags(text):
    """把「自主任务」文本拆成 (flags, prompt)：
    flags 须在 prompt 之前；`--flag val` / `--flag=val` 识别为 claude 参数，
    首个非 flag 词及其后视为 prompt。纯文本输入 → ([], 全文)。"""
    try:
        toks = shlex.split(text)
    except ValueError:
        toks = (text or "").split()
    if toks and toks[0] == "claude":
        toks = toks[1:]
    args, i, n = [], 0, len(toks)
    while i < n:
        t = toks[i]
        if not t.startswith("-"):
            return args, " ".join(toks[i:])
        args.append(t)
        if "=" not in t and t in _AGENT_VALUE_FLAGS and i + 1 < n and not toks[i + 1].startswith("-"):
            args.append(toks[i + 1])
            i += 1
        i += 1
    return args, ""


def _drop_flag(flags, name):
    """移除 flags 里的裸 flag（连同相邻值 token）与 --name=val 一体形式。"""
    out, i = [], 0
    while i < len(flags):
        t = flags[i]
        if t == name:
            if i + 1 < len(flags) and not flags[i + 1].startswith("-"):
                i += 1
            i += 1
            continue
        if t.startswith(name + "="):
            i += 1
            continue
        out.append(t)
        i += 1
    return out


def _flag_value(flags, name, default=None):
    """取首个 `--name val` / `--name=val` 的值。"""
    for i, t in enumerate(flags):
        if t == name and i + 1 < len(flags):
            return flags[i + 1]
        if t.startswith(name + "="):
            return t.split("=", 1)[1]
    return default


def _fence_list(s):
    return [x.strip() for x in (s or "").split(",") if x.strip()]


# 内置/随 CLI 分发的技能（无本地 SKILL.md，走 Skill 工具）
_BUILTIN_SKILLS = sorted(set([
    "frontend-design:frontend-design", "dataviz", "update-config", "keybindings-help",
    "code-review", "simplify", "fewer-permission-prompts", "loop", "claude-api",
    "workflow-authoring", "run", "init", "security-review",
]))


def _skill_desc(path):
    """从 SKILL.md frontmatter 取 description（支持行内与 YAML `>`/`|` 折叠块）。"""
    try:
        with open(path, encoding="utf-8") as f:
            head = f.read(2000)
    except OSError:
        return ""
    if not head.startswith("---"):
        return ""
    end = head.find("\n---", 3)
    lines = head[: end if end != -1 else len(head)].splitlines()
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*description:\s*(.*)$", ln)
        if not m:
            continue
        val = m.group(1).strip()
        if val and val not in ("|", ">", "|-", ">-"):
            return val.strip('"').strip("'")
        # 折叠块：跟后续缩进行合并
        parts = []
        for sub in lines[i + 1:]:
            if sub.startswith(("#", " ", "\t")) and sub.strip():
                parts.append(sub.strip())
            elif not sub.strip():
                continue
            else:
                break
        return " ".join(parts).strip()
    return ""


def _list_skills():
    """枚举可调用技能（含 frontmatter 描述）：用户级 / 项目级 / 插件市场 + 内置。"""
    out, seen = [], set()
    home = os.path.expanduser("~")
    base = os.path.dirname(os.path.abspath(__file__))

    def add(path, nm, source):
        if nm in seen:
            return
        seen.add(nm)
        out.append({"name": nm, "source": source, "desc": _skill_desc(path) if path else "",
                    "path": path or ""})

    for root in (os.path.join(base, ".claude", "skills"),
                 os.path.join(home, ".claude", "skills")):
        if not os.path.isdir(root):
            continue
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for nm in names:
            p = os.path.join(root, nm, "SKILL.md")
            if os.path.isfile(p):
                add(p, nm, "user")
    mp = os.path.join(home, ".claude", "plugins", "marketplaces")
    if os.path.isdir(mp):
        for vendor in os.listdir(mp):
            sp = os.path.join(mp, vendor, "skills")
            if not os.path.isdir(sp):
                continue
            for nm in os.listdir(sp):
                p = os.path.join(sp, nm, "SKILL.md")
                if os.path.isfile(p):
                    add(p, nm, "plugin")
    for b in _BUILTIN_SKILLS:
        add(None, b, "builtin")
    return sorted(out, key=lambda x: x["name"])


# TUI 式 `/` 菜单：内置命令（可与模型一起用的等价物）+ 技能/插件 + MCP 工具
_SLASH_COMMANDS = ["model", "clear", "compact", "mcp", "skills", "permissions", "config",
                   "resume", "rewind", "memory", "add-dir", "agents"]


def _mcp_tool_names():
    """hexstrike MCP 暴露的工具名（@mcp.tool 函数，与会话可见的 mcp__hexstrike-ai__* 一致）。
    注意：tools/*.json 的模板名是内部 build 键（如 amass），并非可调用工具名，不入菜单。"""
    try:
        import hexstrike_mcp as hm
        import inspect
        import re as _re
        src = inspect.getsource(hm.setup_mcp_server)
        return sorted(set(_re.findall(r"@mcp\.tool\(\)[\s\S]*?def\s+(\w+)", src)))
    except Exception:
        return []


def _other_mcp_servers():
    """~/.claude.json 里除 hexstrike 外的 MCP server（仅列名，工具由会话内连接提供）。"""
    try:
        cfg = json.load(open(os.path.join(os.path.expanduser("~"), ".claude.json")))
        return sorted(k for k in (cfg.get("mcpServers") or {}).keys() if k != "hexstrike-ai")
    except Exception:
        return []


def _mcp_state():
    """控制台会话级启用的 MCP 服务器（不写全局 ~/.claude.json）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-servers-state.json")
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}


def _mcp_enabled_servers():
    """按状态过滤 ~/.claude.json 的 mcpServers：hexstrike-ai 必需，其余默认启用可停用。"""
    cfg = {}
    try:
        cfg = json.load(open(os.path.join(os.path.expanduser("~"), ".claude.json"))).get("mcpServers") or {}
    except Exception:
        pass
    st = _mcp_state()
    return {n: c for n, c in cfg.items()
            if c is not None and (n == "hexstrike-ai" or st.get(n, True))}


def _mcp_status():
    """/mcp 面板：列出配置的 MCP 服务器 + 连接/工具/启用状态。hexstrike-ai 是进程内直连。"""
    out = []
    cfg = {}
    try:
        cfg = json.load(open(os.path.join(os.path.expanduser("~"), ".claude.json")))
    except Exception:
        pass
    servers = dict(cfg.get("mcpServers") or {})
    base = os.path.dirname(os.path.abspath(__file__))
    servers.setdefault("hexstrike-ai", {"command": sys.executable,
                                        "args": [os.path.join(base, "hexstrike_mcp.py")]})
    hex_names = _mcp_tool_names()
    st = _mcp_state()
    for name, conf in servers.items():
        locked = name == "hexstrike-ai"
        rec = {"name": name,
               "connected": name == "hexstrike-ai",
               "tools": len(hex_names) if name == "hexstrike-ai" else 0,
               "enabled": locked or st.get(name, True),
               "locked": locked}
        if isinstance(conf, dict):
            rec["command"] = conf.get("command", "")
            rec["args"] = " ".join(map(str, conf.get("args") or []))[:80]
            rec["type"] = conf.get("type", "")
        out.append(rec)
    return out


def _claude_home():
    return os.path.join(os.path.expanduser("~"), ".claude")


def _settings_items():
    items = []
    for p in ([os.path.join(os.path.dirname(os.path.abspath(__file__)), ".claude", "settings.json"),
               os.path.join(os.path.dirname(os.path.abspath(__file__)), ".claude", "settings.local.json"),
               os.path.join(_claude_home(), "settings.json")]):
        if os.path.isfile(p):
            try:
                n = len(open(p, encoding="utf-8").read())
            except OSError:
                n = 0
            items.append({"name": p, "desc": f"{os.path.basename(p)} · {n} 字符"})
    return items or [{"name": "未发现 settings.json", "desc": ""}]


def _memory_items():
    cwd = os.path.dirname(os.path.abspath(__file__))
    memdir = os.path.join(_claude_home(), "projects", cwd.replace(os.sep, "-").replace(".", "-"), "memory")
    items = []
    if os.path.isdir(memdir):
        for fn in sorted(os.listdir(memdir)):
            if not fn.endswith(".md"):
                continue
            p = os.path.join(memdir, fn)
            try:
                head = open(p, encoding="utf-8").read()[:120].replace("\n", " ")
            except OSError:
                head = ""
            items.append({"name": fn, "desc": head or "(空)"})
    return items or [{"name": "尚无项目记忆", "desc": "memory 目录未生成或在别处"}]


def _agent_files():
    items = []
    for root in (os.path.join(os.path.dirname(os.path.abspath(__file__)), ".claude", "agents"),
                 os.path.join(_claude_home(), "agents")):
        if not os.path.isdir(root):
            continue
        for fn in sorted(os.listdir(root)):
            if fn.endswith(".md"):
                items.append({"name": fn.replace(".md", ""), "desc": os.path.join(root, fn)})
    return items or [{"name": "未发现 agent 定义", "desc": ".claude/agents/ 或 ~/.claude/agents/ 下无 .md"}]


def _claude_dirs():
    cwd = os.path.dirname(os.path.abspath(__file__))
    cands = [os.path.join(cwd, "CLAUDE.md"),
             os.path.join(cwd, ".claude", "CLAUDE.md"),
             os.path.join(cwd, ".claude", "CLAUDE.local.md"),
             os.path.join(_claude_home(), "CLAUDE.md")]
    return [{"name": p, "desc": f"{os.path.getsize(p)} 字符" if os.path.isfile(p) else "不存在"}
            for p in cands]


def _panel(name):
    """TUI 式面板数据：命令 → {title, kind, ...}。kind: mcp/skills/model/list/action。"""
    if name == "mcp":
        return {"title": "MCP 服务器", "kind": "mcp", "servers": _mcp_status()}
    if name in ("skills", "skill"):
        return {"title": "技能", "kind": "skills", "skills": _list_skills()}
    if name == "model":
        return {"title": "模型", "kind": "model",
                "options": [{"name": "", "desc": "默认（与当前会话一致）"},
                            {"name": "opus", "desc": "最强"},
                            {"name": "sonnet", "desc": "均衡"},
                            {"name": "haiku", "desc": "快"}]}
    if name == "permissions":
        return {"title": "权限", "kind": "list",
                "hint": "headless agent 默认 --permission-mode bypassPermissions（在输入框文本里可覆盖）；工具白名单在发起前设置。",
                "items": [{"name": "--permission-mode", "desc": "当前默认 bypassPermissions（可在目标文本里覆盖）"},
                          {"name": "工具白名单", "desc": "左侧「工具白名单」勾选 + 逗号列表 → 注入 --allowedTools"}]}
    if name == "config":
        return {"title": "配置", "kind": "list", "items": _settings_items()}
    if name == "memory":
        return {"title": "项目记忆", "kind": "list", "items": _memory_items()}
    if name == "agents":
        return {"title": "Agents", "kind": "list", "items": _agent_files()}
    if name == "add-dir":
        return {"title": "上下文目录（CLAUDE.md）", "kind": "list", "items": _claude_dirs()}
    if name == "clear":
        return {"title": "清空 / 重开", "kind": "action", "action": "clear",
                "desc": "不续上一会话、重开新会话（等价 /clear）"}
    if name == "compact":
        return {"title": "压缩上下文", "kind": "action", "action": "compact",
                "desc": "续跑时可加 --autocompact，压缩长上下文后继续同会话"}
    if name == "resume":
        return {"title": "继续 / 续会话", "kind": "action", "action": "resume",
                "desc": "复用最近一次 agent 会话继续（等价 /resume，配合「🔗 续上一会话」）"}
    if name == "rewind":
        return {"title": "回退", "kind": "action", "action": "rewind",
                "desc": "headless 无多步回退 UI；用 中断 → 调整 → 继续 达到近似效果"}
    return None


def _menu():
    items = [{"kind": "cmd", "name": c, "label": "/" + c} for c in _SLASH_COMMANDS]
    for s in _list_skills():
        items.append({"kind": "skill", "name": s["name"], "source": s["source"],
                      "label": "/" + s["name"], "desc": s.get("desc", "")})
    for n in _mcp_tool_names():
        items.append({"kind": "mcp", "name": n, "label": "mcp__hexstrike-ai__" + n, "server": "hexstrike-ai"})
    others = _other_mcp_servers()
    for srv in others:
        items.append({"kind": "mcp-server", "name": srv, "label": "mcp 服务器: " + srv, "server": srv})
    return items


def _resolve_skill(prompt, cwd=None):
    """prompt 以 `/技能名 用户补充` 开头 → 定位 SKILL.md → 展开为
    `--append-system-prompt-file <tmp>` 注入（确定性，不靠模型猜）。
    支持命名空间 `plugin:skill`、markdowns 子目录布局、插件市场技能目录。
    返回 (extra_args, new_prompt)；`/xxx` 但技能不存在返回 False。"""
    m = re.match(r"^/([\w.-]+(?::[\w.-]+)?)(?:\s+(.*))?$", prompt.strip(), re.S)
    if not m:
        return None
    name, rest = m.group(1), (m.group(2) or "").strip()
    bare = name.split(":")[-1]
    base = cwd or os.path.dirname(os.path.abspath(__file__))
    home = os.path.expanduser("~")
    roots = [os.path.join(base, ".claude", "skills"),
             os.path.join(home, ".claude", "skills")]
    hits = []
    for root in roots:
        for nm in (name, bare):
            for cand in (os.path.join(root, nm, "SKILL.md"),
                         os.path.join(root, nm, "markdowns", nm, "SKILL.md")):
                if os.path.isfile(cand):
                    hits.append(cand)
    mp = os.path.join(home, ".claude", "plugins", "marketplaces")
    try:
        import glob
        pat = os.path.join(mp, "*", "skills", "*", "SKILL.md")
        for cand in glob.glob(pat):
            if os.path.basename(os.path.dirname(cand)) == bare:
                hits.append(cand)
    except Exception:
        pass
    path = next(iter(hits), None)
    if not path:
        return False
    content = open(path, encoding="utf-8").read()
    if content.startswith("---"):
        end = content.find("\n---", 3)
        if end != -1:
            content = content[end + 4:].strip("\n")
    cm = re.search(r"<command[^>]*>(.*?)</command>", content, re.S)
    body = (cm.group(1) if cm else content).strip()
    if len(body) > 30000:                       # 防超大技能撑爆 system prompt
        body = body[:30000] + "\n……（技能正文过长已截断）"
    if rest:
        body = body.replace("<args>", rest) if "<args>" in body else body
    tmp = os.path.join(tempfile.gettempdir(), f"hexdash_skill_{name.replace(':','-')}_{uuid.uuid4().hex[:6]}.md")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"# 技能：{name}\n\n{body}\n\n按以上技能执行。目标：{rest}\n")
    return ["--append-system-prompt-file", tmp], rest or f"执行 {name} 技能。"


def _build_agent_cmd(session_id, text, resume=False, model="", fence="", suffix=""):
    """组装 headless `claude -p` 命令：
    - 文本里的 claude flags 原样透传（`--session-id`/`--resume`/`--output-format` 硬控/接管）；
    - `/技能` → SKILL.md 确定性注入；model/fence 由控制台控件给值。"""
    flags, prompt = _split_agent_flags(text)
    if prompt:
        skill = _resolve_skill(prompt)
        if skill:
            flags += skill[0]
            prompt = skill[1]
        elif skill is False:
            # 本地没有 SKILL.md（内置/插件技能）：不硬报错，保留原文并引导模型
            # 走 Skill 工具（这是这类技能唯一正确的调用通道）。
            prompt = ("（技能未能在本地解析成 SKILL.md，请用 Skill 工具调用它执行。）\n"
                      + prompt)
    # 会话生命周期由控制台记账：接管 --session-id / --resume / --continue
    sid = _flag_value(flags, "--session-id")
    flags = _drop_flag(flags, "--session-id")
    flags = _drop_flag(flags, "--resume")
    flags = _drop_flag(flags, "--continue")
    # 硬控：输出格式必须 stream-json（日志流解析依赖）
    flags = [f for f in flags if f != "--output-format" and not f.startswith("--output-format=")
             and f not in ("-p", "--print")]
    has_perm = any(f == "--permission-mode" or f.startswith("--permission-mode=") for f in flags)
    if not has_perm:
        flags += ["--permission-mode", "bypassPermissions"]
    has_model = any(f == "--model" or f.startswith("--model=") for f in flags)
    if model and not has_model:
        flags += ["--model", model]
    fence_tools = _fence_list(fence)
    if fence_tools:
        has_tools = any(f == "--allowedTools" or f.startswith("--allowedTools=")
                        or f == "--allowed-tools" for f in flags)
        if not has_tools:
            flags += ["--allowedTools", ",".join(fence_tools)]
    if not prompt:
        prompt = "继续执行当前 hexstrike 任务，用中文简洁总结。"
    if suffix:
        prompt += "\n\n" + suffix
    cmd = ["claude", "-p"]
    cmd += ["--resume", sid or session_id] if resume else ["--session-id", session_id]
    cmd += flags + [prompt, "--output-format", "stream-json", "--verbose"]
    has_mcp = any(f == "--mcp-config" or f.startswith("--mcp-config=") for f in flags)
    if not has_mcp:
        # 会话级启用集 ≠ 全局配置 → 生成 --mcp-config 让 headless 只连启用的服务器
        try:
            cfg_keys = set((json.load(open(os.path.join(os.path.expanduser("~"), ".claude.json")))
                            .get("mcpServers") or {}).keys())
            en = _mcp_enabled_servers()
            if en and set(en) != cfg_keys:
                tmp = os.path.join(tempfile.gettempdir(), f"hexdash_mcp_{uuid.uuid4().hex[:6]}.json")
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump({"mcpServers": en}, fh, ensure_ascii=False)
                cmd += ["--mcp-config", tmp]
        except Exception:
            pass
    return cmd


def _append_agent_events(job, proc):
    """读完 proc 的 stream-json 事件写入 job.log；进程结束后返回 returncode。"""
    notes = []
    for line in proc.stdout or []:
        try:
            s = line.strip()
            if not s.startswith("{"):
                if s:
                    notes.append(s)
                continue
            ev = json.loads(s)
            msg = ev.get("message")
            if not isinstance(msg, dict):
                continue
            for c in msg.get("content") or []:
                if not isinstance(c, dict):
                    continue
                t = c.get("type")
                if t == "text" and c.get("text"):
                    job.log.append(f'<span class="t">{_ts()}</span> <span class="ok">{c["text"]}</span>')
                elif t == "tool_use":
                    name = c.get("name", "")
                    job.log.append(f'<span class="t">{_ts()}</span> <span class="ac">⚙ {name}</span>')
                    inp = c.get("input") if isinstance(c.get("input"), dict) else {}
                    key = next((k for k in ("target", "findings_json", "query", "goal") if k in inp), None)
                    val = str(inp.get(key, "")) if key else ""
                    if name.startswith("mcp__hexstrike-ai__") and val:
                        job.log.append(f'<span class="t">{_ts()}</span> <span class="cmd">'
                                       f'&nbsp;&nbsp;↳ {val[:110]}</span>')
        except Exception:
            continue
    rc = proc.wait()
    if rc != 0 and notes:
        job.log.append(f'<span class="t">{_ts()}</span> '
                       f'<span class="err">! claude 退出码 {rc}: {notes[-1][:120]}</span>')
    return rc


def _log_skill(job, cmd):
    """命令里若注入了技能，日志显式标出「已注入技能」，避免看起来像悄悄执行。"""
    if "--append-system-prompt-file" not in cmd:
        return
    i = cmd.index("--append-system-prompt-file") + 1
    if i >= len(cmd):
        return
    base = os.path.basename(cmd[i])
    name = base.replace("hexdash_skill_", "").rsplit("_", 1)[0]
    job.log.append(f'<span class="t">{_ts()}</span> <span class="ac">⚙ 已注入技能 /{name}</span>')


def _run_agent_job(job, params):
    """首跑：`claude -p --session-id <id>` 多轮自主执行，可随时中断、后 `--resume` 续跑。

    `claude -p` 加载同一套 hexstrike MCP 工具（user scope），以 bypassPermissions
    免审批自主执行，自我规划、调用工具、写快照，与当前会话同一模型链路。事件流经
    stream-json 转成前端日志。
    """
    goal = (params.get("goal") or "").strip()
    if not goal:
        job.status = "error"
        job.error = "goal 为空"
        return
    try:
        s = _snapshot_db.stats()
        suffix = ("（当前资产快照：%d 资产 · 确认漏洞 %d · 待复核 %d。"
                  "需要时可调 snapshot_report / query_assets 看上下文；若有新增或变更，"
                  "完成后调 snapshot_update 写回快照。最后用中文简洁总结。）"
                  % (s["total_assets"], s["total_confirmed"], s["pending_review"]))
    except Exception:
        suffix = ""
    job.session_id = str(uuid.uuid4())
    _jobs.last_agent = job
    cwd = os.path.dirname(os.path.abspath(__file__))
    job.log.append(f'<span class="t">{_ts()}</span> <span class="ac">🧠 交给 Claude Agent（headless）· {goal[:60]}</span>')
    try:
        cmd = _build_agent_cmd(job.session_id, goal, resume=False,
                               model=params.get("model", ""), fence=params.get("fence", ""),
                               suffix=suffix)
        _log_skill(job, cmd)
        job.log.append(f'<span class="t">{_ts()}</span> <span class="cmd">$ {" ".join(cmd[:6])} …</span>')
        job.proc = subprocess.Popen(cmd, cwd=cwd,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, stdin=subprocess.DEVNULL, env=dict(os.environ))
        _append_agent_events(job, job.proc)
        if job.status in ("paused", "cancelled"):
            return
        job.result = {"rc": job.proc.returncode, "note": "agent 执行完毕"}
        job.status = "done"
    except Exception as e:
        job.status = "error"
        job.error = str(e)
        job.log.append(f'<span class="t">{_ts()}</span> <span class="err">✖ {e}</span>')


def _run_agent_resume(job, text, model="", fence=""):
    """续跑：`claude -p --resume <id> <用户调整>`，同一会话带记忆继续自主执行。"""
    cwd = os.path.dirname(os.path.abspath(__file__))
    job.status = "running"
    _jobs.last_agent = job
    job.log.append(f'<span class="t">{_ts()}</span> <span class="ac">▶ 继续会话</span>'
                   + (f' <span class="cmd">「{text[:60]}」</span>' if text else ''))
    try:
        cmd = _build_agent_cmd(job.session_id, text or "继续执行当前任务。",
                               resume=True, model=model, fence=fence)
        _log_skill(job, cmd)
        job.log.append(f'<span class="t">{_ts()}</span> <span class="cmd">$ {" ".join(cmd[:6])} …</span>')
        job.proc = subprocess.Popen(cmd, cwd=cwd,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, stdin=subprocess.DEVNULL, env=dict(os.environ))
        _append_agent_events(job, job.proc)
        if job.status in ("paused", "cancelled"):
            return
        job.result = {"rc": job.proc.returncode, "note": "agent 执行完毕"}
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
        if _snapshot_db:
            _snapshot_db.load()                      # 每请求重读，跨进程（agent）同步
        route = urllib.parse.urlparse(self.path).path
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if route in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif route == "/api/stats":
            self._json(_snapshot_db.stats())
        elif route == "/api/assets":
            self._json(list(_snapshot_db.data["assets"].values()))
        elif route == "/api/skills":
            self._json({"skills": _list_skills()})
        elif route == "/api/mcp":
            self._json({"servers": _mcp_status()})
        elif route == "/api/skill/read":
            nm = q.get("name", [""])[0]
            hit = next((s for s in _list_skills() if s["name"] == nm and s.get("path")), None)
            if not hit:
                self._json({"error": "技能未找到或无本地文件"}, 404)
            else:
                try:
                    body = open(hit["path"], encoding="utf-8").read()
                except OSError:
                    self._json({"error": "无法读取 SKILL.md"}, 500)
                else:
                    self._json({"name": nm, "path": hit["path"], "content": body[:4000]})
        elif route == "/api/menu":
            self._json({"items": _menu()})
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
            if route.startswith("/api/panel/"):
                p = _panel(route.split("/")[-1])
                if p is None:
                    self._json({"error": "未知名面板"}, 404)
                else:
                    self._json(p)
            else:
                self.send_error(404)

    def do_POST(self):
        if _snapshot_db:
            _snapshot_db.load()                      # 每请求重读，避免基于陈旧内存
        route = urllib.parse.urlparse(self.path).path
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(ln).decode("utf-8") or "{}") if ln else {}
        except json.JSONDecodeError:
            return self._json({"error": "请求体不是合法 JSON"}, 400)
        if route == "/api/jobs":
            active = _jobs.active_job()
            if active:
                return self._json({"error": f"已有活动任务（{active.kind} {active.job_id} · {active.status}），先完成或停止它再发起新任务"}, 409)
            kind = body.get("type", "scan")
            job = _jobs.create(kind, kind)
            if kind == "agent" and (body.get("resume_session") or ""):
                goal = body.get("goal") or ""
                rs = (body.get("resume_session") or "").strip()
                sid = _jobs.last_agent.session_id if (rs == "last" and _jobs.last_agent) \
                      else (rs if rs != "last" else "")
                if not sid:
                    self._json({"error": "没有可续跑的上一 agent 会话"}, 400)
                    return
                job.session_id = sid
                threading.Thread(target=_run_agent_resume,
                                 args=(job, goal, body.get("model", ""), body.get("fence", "")),
                                 daemon=True).start()
                self._json(_jobs.render(job), 202)
                return
            _start_job(job, body)
            self._json(_jobs.render(job), 202)
        elif route.endswith("/interrupt"):
            jid = route.split("/")[-2]
            job = _jobs.get(jid)
            if job and job.kind == "agent" and job.status == "running" and job.proc:
                job.status = "paused"
                try:
                    job.proc.terminate()
                except Exception:
                    pass
                job.log.append(f'<span class="t">{_ts()}</span> <span class="hot">⏸ 已中断 —— 会话已保留，可输入调整后继续</span>')
            self._json(_jobs.render(job) if job else {"error": "not found"})
        elif route.endswith("/resume"):
            jid = route.split("/")[-2]
            job = _jobs.get(jid)
            if job and job.kind == "agent" and job.status == "paused" and job.session_id:
                text = (body.get("text") or "").strip()
                job.status = "running"
                job.error = ""
                threading.Thread(target=_run_agent_resume,
                                 args=(job, text, body.get("model", ""), body.get("fence", "")),
                                 daemon=True).start()
                self._json(_jobs.render(job))
            else:
                self._json({"error": "job 不可续跑（非 agent / 非暂停 / 无会话）"}, 400)
        elif route.endswith("/cancel"):
            jid = route.split("/")[-2]
            job = _jobs.get(jid)
            if job and job.status in ("running", "paused"):
                job.status = "cancelled"
                if job.kind == "agent" and job.proc:
                    try:
                        job.proc.terminate()
                    except Exception:
                        pass
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
            keys = body.get("keys", []); n = 0; gone = []
            for k in keys:
                if _snapshot_db.data["assets"].pop(k, None):
                    gone.append(k); n += 1
            _snapshot_db.save(remove=gone)
            self._json({"deleted": n})
        elif route == "/api/assets/merge":
            keep = body.get("keep"); keys = body.get("keys", [])
            target = _snapshot_db.data["assets"].get(keep)
            if not target:
                return self._json({"error": "主资产不存在"}, 404)
            gone = []
            for k in keys:
                other = _snapshot_db.data["assets"].pop(k, None)
                if not other:
                    continue
                gone.append(k)
                target["tags"] = memory._clean_tags(target.get("tags", []) + other.get("tags", []))
                for f in other.get("findings", []):
                    if f not in target.setdefault("findings", []):
                        target["findings"].append(f)
            _snapshot_db._recompute_risk(target)
            _snapshot_db.save(remove=gone)
            self._json({"merged": len(keys)})
        elif route == "/api/mcp/toggle":
            name = body.get("name", ""); enabled = bool(body.get("enabled"))
            if name == "hexstrike-ai":
                return self._json({"error": "hexstrike-ai 为平台必需，不能停用"}, 400)
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-servers-state.json")
            st = {}
            try:
                st = json.load(open(p, encoding="utf-8"))
            except Exception:
                pass
            st[name] = enabled
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(st, fh, ensure_ascii=False, indent=2)
            self._json({"servers": _mcp_status()})
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
                active = _jobs.active_job()
                if active:
                    self._json({"error": f"已有活动任务（{active.kind} {active.job_id} · {active.status}），先完成或停止它再扫描"}, 409)
                    return
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
                gone = [k for k in keys if _snapshot_db.data["assets"].pop(k, None)]
                _snapshot_db.save(remove=gone)
                self._json({"ok": True, "message": f"已删除 {len(gone)} 个资产", "matched": keys})
            elif op == "merge":
                keys = _resolve_keys(text + " " + (p.get("keep") or ""))
                if len(keys) < 2:
                    return self._json({"error": "合并需要至少匹配到 2 个资产"}, 400)
                keep = keys[0]
                target = _snapshot_db.data["assets"].get(keep)
                merged = 0; gone = []
                for k in keys[1:]:
                    other = _snapshot_db.data["assets"].pop(k, None)
                    if not other:
                        continue
                    gone.append(k)
                    target["tags"] = memory._clean_tags(target.get("tags", []) + other.get("tags", []))
                    for f in other.get("findings", []):
                        if f not in target.setdefault("findings", []):
                            target["findings"].append(f)
                    merged += 1
                _snapshot_db._recompute_risk(target)
                _snapshot_db.save(remove=gone)
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


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _listening_pids(port: int) -> list:
    try:
        r = subprocess.run(["lsof", "-nP", "-tiTCP:" + str(port), "-sTCP:LISTEN"],
                           capture_output=True, text=True, timeout=5)
        return [l for l in r.stdout.split() if l.strip().isdigit()]
    except Exception:
        return []


def spawn_dashboard(snapshot_path: str = "", port: int = DEFAULT_PORT,
                    host: str = "127.0.0.1", open_browser: bool = True) -> dict:
    """独立进程式控制台入口（幂等，全平台唯一运行形态）。

    端口已监听 → 直接复用；否则拉起 dashboard.py 独立进程
    （start_new_session，不随调用方会话结束而退出，日志 /tmp/hexdash.log）。
    与 ~/.zshrc 的 `hexdash` 函数是同一形态，二者任一调用都作用于同一进程。
    """
    url = f"http://{host}:{int(port)}/"
    if _port_open(host, int(port)):
        time.sleep(0.2)          # 避开「刚 stop 端口未关」的竞态窗口
        if _port_open(host, int(port)):
            if open_browser:
                webbrowser.open(url)
            return {"url": url, "port": int(port), "status": "running",
                    "created": False,
                    "snapshot": _snapshot_db.stats() if _snapshot_db else None}
    here = os.path.dirname(os.path.abspath(__file__))
    cmd = [sys.executable, os.path.abspath(__file__), snapshot_path, str(int(port))]
    with open("/tmp/hexdash.log", "ab") as logf:
        subprocess.Popen(cmd, cwd=here, stdin=subprocess.DEVNULL,
                         stdout=logf, stderr=subprocess.STDOUT,
                         start_new_session=True)
    for _ in range(20):
        if _port_open(host, int(port)):
            break
        time.sleep(0.5)
    ok = _port_open(host, int(port))
    if open_browser:
        webbrowser.open(url)
    return {"url": url, "port": int(port), "status": "running" if ok else "starting",
            "created": True, "snapshot": None}


def stop_dashboard_process(port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> dict:
    """按端口停止独立 dashboard 进程（与 hexdash stop 语义一致）。"""
    pids = _listening_pids(int(port))
    if not pids:
        return {"status": "not_running", "port": int(port)}
    for pid in pids:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    return {"status": "stopped", "port": int(port), "pids": pids}


if __name__ == "__main__":
    snap = sys.argv[1] if len(sys.argv) > 1 else ""
    port = DEFAULT_PORT
    if len(sys.argv) > 2 and str(sys.argv[2]).strip().isdigit():
        port = int(sys.argv[2])
    print(json.dumps(start_dashboard(snap, port=port, host="127.0.0.1"),
                     ensure_ascii=False), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_dashboard(port=port)