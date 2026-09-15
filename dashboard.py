#!/usr/bin/env python3
"""HexStrike 本地可视化仪表盘（改造④）—— 资产快照 + 三态验证结果。

零第三方依赖（标准库 http.server + webbrowser），读 memory.AssetSnapshot 的
ai-security-snapshot.json 实时出可视化：风险分布 + 资产表 + finding/verdict 详情。
数据接口 /api/stats、/api/assets；页面 GET / 打开。图表用 SVG 手绘，状态色遵循
dataviz status palette 且一律带文字标签（不单靠颜色）。
"""

import json
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import memory

DEFAULT_PORT = 8765

# 状态色：status palette（skill 已验证）+ 中性灰辅助；均配文本标签
RISK_COLORS = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219",
               "low": "#9a9a97", "normal": "#0ca30c", "unassessed": "#b9b8b3"}
VERDICT_COLORS = {"confirmed": "#0ca30c", "refuted": "#9a9a97", "unverifiable": "#fab219"}
VERDICT_LABEL = {"confirmed": "已复现", "refuted": "未复现", "unverifiable": "待复核"}
RISK_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
              "normal": "正常", "unassessed": "未评估"}

PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HexStrike 资产仪表盘</title>
<style>
:root{--surface:#fcfcfb;--surface2:#f1f0ec;--ink:#0b0b0b;--ink2:#52514e;--line:#e2e0da;
  --good:#0ca30c;--warn:#fab219;--serious:#ec835a;--crit:#d03b3b;--muted:#9a9a97;
  --mono:ui-monospace,SFMono-Regular,Menlo,monospace;}
@media (prefers-color-scheme:dark){:root{--surface:#1a1a19;--surface2:#242422;--ink:#fff;
  --ink2:#c3c2b7;--line:#33332f;}}
*{box-sizing:border-box}
body{margin:0;background:var(--surface);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:20px 24px 60px}
header{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:14px}
h1{font-size:20px;margin:0}
.sub{color:var(--ink2);font-size:12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.tile{background:var(--surface2);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile .num{font-size:26px;font-weight:650}
.tile .lbl{color:var(--ink2);font-size:12px;margin-top:2px}
.row{display:grid;grid-template-columns:300px 1fr;gap:18px;margin:10px 0 22px}
@media(max-width:760px){.row{grid-template-columns:1fr}}
.card{background:var(--surface2);border:1px solid var(--line);border-radius:10px;padding:14px}
.card h3{margin:0 0 10px;font-size:14px}
.legend{display:grid;gap:6px;margin-top:10px;font-size:13px}
.legend .it{display:flex;align-items:center;gap:8px}
.sw{width:12px;height:12px;border-radius:3px;flex:none}
.count{margin-left:auto;color:var(--ink2)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:1px 8px;border-radius:99px;font-size:12px;
  border:1px solid transparent;white-space:nowrap}
.badge .dot{width:8px;height:8px;border-radius:50%}
.tag{display:inline-block;background:var(--line);border-radius:99px;padding:0 7px;font-size:11px;margin:1px 2px}
.filters{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.filters input,.filters select{background:var(--surface);border:1px solid var(--line);color:var(--ink);
  border-radius:8px;padding:7px 10px;font-size:13px}
.filters input{min-width:220px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--ink2);font-weight:550;position:sticky;top:0;background:var(--surface2)}
tbody tr{cursor:pointer}
tbody tr:hover td{background:var(--surface)}
.findings{margin:0 10px 8px;padding:10px;background:var(--surface);border:1px solid var(--line);border-radius:8px}
.findings .f{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;padding:6px 0;border-bottom:1px dotted var(--line)}
.findings .f:last-child{border-bottom:none}
.mono{font-family:var(--mono);font-size:12px;word-break:break-all;color:var(--ink2)}
.verdict{font-size:12px;color:var(--ink2)}
.empty{color:var(--ink2);padding:20px;text-align:center}
</style>
</head>
<body><div class="wrap">
<header><h1>HexStrike 资产仪表盘</h1>
<span class="sub" id="meta"></span></header>

<div class="tiles">
  <div class="tile"><div class="num" id="tTotal">–</div><div class="lbl">资产总数</div></div>
  <div class="tile"><div class="num" id="tVuln">–</div><div class="lbl">当前确认漏洞</div></div>
  <div class="tile"><div class="num" id="tPending">–</div><div class="lbl">待复核</div></div>
  <div class="tile"><div class="num" id="tHigh">–</div><div class="lbl">高危以上资产</div></div>
</div>

<div class="row">
  <div class="card"><h3>风险分布</h3><svg id="donut" viewBox="0 0 200 200" width="200" height="200"></svg>
    <div class="legend" id="legend"></div></div>
  <div class="card"><h3>资产明细</h3>
    <div class="filters"><input id="q" placeholder="搜索 target / host / tags / 端口 ">
    <select id="risk"><option value="">全部风险</option></select></div>
    <table><thead><tr><th>目标</th><th>端口/协议</th><th>风险</th><th>漏洞</th><th>待复核</th><th>首见</th><th>末见</th><th>tags</th></tr></thead>
    <tbody id="rows"></tbody></table>
    <div class="empty" id="empty" hidden>无匹配资产</div>
  </div>
</div>
</div>

<script>
const SZ=200,R=78,C=SZ/2,PR=50;
const RR={critical:"#d03b3b",high:"#ec835a",medium:"#fab219",low:"#9a9a97",normal:"#0ca30c",unassessed:"#b9b8b3"};
const RL={critical:"严重",high:"高危",medium:"中危",low:"低危",normal:"正常",unassessed:"未评估"};
const VL={confirmed:"已复现",refuted:"未复现",unverifiable:"待复核"};
const VC={confirmed:"#0ca30c",refuted:"#9a9a97",unverifiable:"#fab219"};
let assets=[];
async function load(){
  const s=await (await fetch("/api/stats")).json();
  document.getElementById("tTotal").textContent=s.total_assets;
  document.getElementById("tVuln").textContent=s.total_confirmed;
  document.getElementById("tPending").textContent=s.pending_review;
  const hi=(s.by_risk.critical||0)+(s.by_risk.high||0);
  document.getElementById("tHigh").textContent=hi;
  document.getElementById("meta").textContent="快照 "+(s.updated_at||"-").replace("T"," ").slice(0,19);
  drawDonut(s.by_risk);
  assets=await (await fetch("/api/assets")).json();
  fillRiskSelect(); render();
}
function drawDonut(by){
  const order=["critical","high","medium","low","normal","unassessed"];
  const vals=order.map(k=>by[k]||0),tot=vals.reduce((a,b)=>a+b,0)||1;
  let ang=-Math.PI/2;
  const segs=[];
  order.forEach((k,i)=>{const v=vals[i];const sweep=(v/tot)*Math.PI*2;
    if(v>0){const a2=ang+sweep;
      const x0=C+R*Math.cos(ang),y0=C+R*Math.sin(ang),x1=C+R*Math.cos(a2),y1=C+R*Math.sin(a2);
      const large=sweep>Math.PI?1:0;
      segs.push({k,count:v,path:`M${C} ${C} L${x0.toFixed(2)} ${y0.toFixed(2)} A${R} ${R} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)} Z`});}
    ang+=sweep;});
  const svg=document.getElementById("donut");
  const center=tot?`<text x="${C}" y="${C-2}" text-anchor="middle" font-size="26" font-weight="650" fill="var(--ink)">${tot}</text>
     <text x="${C}" y="${C+16}" text-anchor="middle" font-size="10" fill="var(--ink2)">资产</text>`:"";
  if(segs.length<=1){
    const sg=segs[0];
    svg.innerHTML=(sg?`<circle cx="${C}" cy="${C}" r="${R}" fill="${RR[sg.k]}"><title>${RL[sg.k]} ${sg.count}</title></circle>`:"")+center;
  }else{
    svg.innerHTML=segs.map(sg=>`<path d="${sg.path}" fill="${RR[sg.k]}" stroke="var(--surface)" stroke-width="1.5"><title>${RL[sg.k]} ${sg.count} (${(100*sg.count/tot).toFixed(0)}%)</title></path>`).join("")+center;
  }
  document.getElementById("legend").innerHTML=order.map(k=>
    `<div class="it"><span class="sw" style="background:${RR[k]}"></span>${RL[k]}
     <span class="count">${by[k]||0}</span></div>`).join("");
}
function fillRiskSelect(){const sel=document.getElementById("risk");
  const cur=sel.value;sel.innerHTML='<option value="">全部风险</option>'+
   Object.keys(RR).map(k=>`<option value="${k}">${RL[k]}</option>`).join("");sel.value=cur;}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function riskBadge(r){return `<span class="badge" style="color:${RR[r]};border-color:${RR[r]}"><span class="dot" style="background:${RR[r]}"></span>${RL[r]}</span>`;}
function render(){
  const q=(document.getElementById("q").value||"").trim().toLowerCase();
  const rf=document.getElementById("risk").value;
  const tbody=document.getElementById("rows");
  const pool=assets.filter(a=>{
    if(rf && a.risk_level!==rf)return false;
    if(q){const hay=(a.target+" "+a.host+" "+a.tags.join(" ")+" "+a.port).toLowerCase();if(!hay.includes(q))return false;}
    return true;});
  tbody.innerHTML=pool.map(a=>{
    const finds=(a.findings||[]).filter(f=>f.verdict==="confirmed"||f.verdict==="unverifiable");
    const inner=finds.length?finds.map(f=>
      `<div class="f"><span class="badge" style="border-color:${VC[f.verdict]};color:${VC[f.verdict]}">${VL[f.verdict]}</span>
      <span><b>${esc(f.type)}</b> · ${esc(f.severity)} · <span class="verdict">${esc(f.matched_at||"")}</span><br>
      <span class="mono">sha256 ${(f.evidence_sha256||"").slice(0,16)}</span><br>
      <span class="mono">${esc(f.repro_command||"")}</span></span></div>`).join("")
      :`<div class="f"><span class="verdict">无已验证 finding</span></div>`;
    const exp=`<div class="findings">${inner}</div>`;
    return `<tr><td><b>${esc(a.target)}</b></td><td class="mono">${a.port}/${a.protocol||"—"}</td>
      <td>${riskBadge(a.risk_level)}</td><td>${a.vuln_count||0}</td><td>${a.pending_review||0}</td>
      <td class="verdict">${(a.first_seen||"").slice(0,10)}</td><td class="verdict">${(a.last_seen||"").slice(0,10)}</td>
      <td>${(a.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join("")||""}</td></tr>
      <tr class="find" hidden><td colspan="8">${exp}</td></tr>`;
  }).join("");
  document.getElementById("empty").hidden=pool.length>0;
}
document.getElementById("q").addEventListener("input",render);
document.getElementById("risk").addEventListener("change",render);
document.getElementById("rows").addEventListener("click",e=>{
  const tr=e.target.closest("tr");if(!tr)return;
  const find=tr.nextElementSibling;
  if(find&&find.classList.contains("find"))find.hidden=!find.hidden;
});
load();setInterval(load,15000);
</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urllib.parse.urlparse(self.path).path
        dash = self.server.dash
        if route in ("/", "/index.html"):
            self._ok(PAGE, "text/html; charset=utf-8")
        elif route == "/api/stats":
            self._ok(json.dumps(dash.snapshot.stats(), ensure_ascii=False),
                     "application/json; charset=utf-8")
        elif route == "/api/assets":
            assets = list(dash.snapshot.data["assets"].values())
            self._ok(json.dumps(assets, ensure_ascii=False), "application/json; charset=utf-8")
        else:
            self.send_error(404)

    def _ok(self, body, ctype):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # 静默访问日志
        pass


class _DashHTTPD(ThreadingHTTPServer):
    def __init__(self, dash, addr):
        self.dash = dash
        super().__init__(addr, _Handler)
        self.daemon_threads = True


class Dash:
    def __init__(self, snapshot_path="", host="127.0.0.1", port=DEFAULT_PORT):
        self.host = host
        self.port = int(port)
        self.snapshot = memory.AssetSnapshot(snapshot_path).load()
        self._httpd = None
        self._thread = None

    def start(self):
        if self._httpd:
            return self
        self._httpd = _DashHTTPD(self, (self.host, self.port))
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def url(self):
        return f"http://{self.host}:{self.port}/"

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


_active = {}
_lock = threading.Lock()


def start_dashboard(snapshot_path: str = "", port: int = DEFAULT_PORT,
                    host: str = "127.0.0.1", open_browser: bool = True) -> dict:
    """启动（或复用）本地仪表盘并可选打开浏览器。返回 {url, port, status, snapshot}。"""
    key = (host, int(port))
    with _lock:
        dash = _active.get(key)
        created = dash is None
        if dash is None:
            dash = Dash(snapshot_path, host, port).start()
            _active[key] = dash
    url = dash.url()
    if open_browser:
        webbrowser.open(url)
    return {"url": url, "port": int(port), "status": "running",
            "created": created, "snapshot": dash.snapshot.stats()}


def stop_dashboard(port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> dict:
    with _lock:
        dash = _active.pop((host, int(port)), None)
    if dash:
        dash.stop()
        return {"status": "stopped", "port": int(port)}
    return {"status": "not_running", "port": int(port)}


if __name__ == "__main__":
    import sys
    print(start_dashboard(sys.argv[1] if len(sys.argv) > 1 else ""))
    import time
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop_dashboard()