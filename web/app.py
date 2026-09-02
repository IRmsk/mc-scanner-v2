# -*- coding: utf-8 -*-
"""Web 面板：零依赖标准库 http.server + 内联单页（借鉴 mdberkey Flask 的分页/搜索/过滤思路与主角 mc-scanner 的轻量 Web）"""
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from storage import db

PAGE_HTML = """<!DOCTYPE html>
<html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MC Scanner V2</title>
<style>
body{font-family:-apple-system,'PingFang SC','Segoe UI',Roboto,Arial,sans-serif;background:#f4f3ee;margin:0;color:#1A1B1C}
.wrap{max-width:980px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:8px 0 4px}
.sub{color:#6B7280;font-size:13px;margin-bottom:14px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.card{flex:1 1 150px;background:#fff;border:1px solid rgba(0,0,0,.08);border-radius:12px;padding:12px}
.card .n{font-size:22px;font-weight:600}
.card .l{font-size:12px;color:#6B7280}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.filters select,.filters input,.filters button{font-size:14px;padding:8px 10px;border:1px solid #E4E3DD;border-radius:8px;background:#fff}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid rgba(0,0,0,.08);border-radius:12px;overflow:hidden;font-size:13px}
th{background:#faf9f6;text-align:left;padding:9px 10px;font-size:12px;color:#6B7280;border-bottom:1px solid #E4E3DD}
td{padding:8px 10px;border-bottom:1px solid #F0EFEA;vertical-align:top}
tr:last-child td{border-bottom:none}
.motd{max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;color:#fff}
.tag-cracked{background:#52C41A}.tag-online{background:#1677FF}.tag-whitelist{background:#FAAD14;color:#6b4e00}
.tag-rejected{background:#EA6668}.tag-unknown{background:#8C8C8C}.tag-offline{background:#bbb}.tag-error{background:#777}
.pg{display:flex;gap:8px;margin-top:12px;align-items:center;font-size:13px}
.pg a,.pg button{text-decoration:none;color:#1677FF;padding:6px 12px;border:1px solid #E4E3DD;border-radius:8px;background:#fff}
@media(max-width:600px){.motd{max-width:120px}table{font-size:12px}th,td{padding:6px}}
</style>
<div class="wrap">
<h1>MC Scanner V2</h1>
<div class="sub" id="sub">加载中...</div>
<div class="cards" id="cards"></div>
<div class="filters">
  <select id="f_auth"><option value="">全部认证</option>
    <option value="cracked">破解(离线)</option><option value="online">正版</option>
    <option value="whitelist">白名单</option><option value="rejected">拒绝</option>
    <option value="unknown">未知</option></select>
  <select id="f_mod"><option value="">全部</option><option value="1">有MOD</option><option value="0">原版</option></select>
  <input id="f_q" placeholder="搜索 MOTD/版本/IP">
  <button onclick="load(1)">查询</button>
</div>
<div style="overflow-x:auto"><table>
<tr><th>IP:端口</th><th>认证</th><th>版本</th><th>MOTD</th><th>在线</th><th>延迟</th><th>更新时间</th></tr>
<tbody id="rows"></tbody></table></div>
<div class="pg"><button onclick="prev()">上一页</button><span id="pg">1</span><button onclick="next()">下一页</button></div>
</div>
<script>
let page=1, limit=50, total=0;
const $=id=>document.getElementById(id);
function esc(s){return (s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function tag(a){const map={cracked:['cracked','破解'],online:['online','正版'],whitelist:['whitelist','白名单'],rejected:['rejected','拒绝'],unknown:['unknown','未知']};
 const t=map[a]||[a,a];return '<span class="tag tag-'+t[0]+'">'+esc(t[1])+'</span>'}
function load(p){
 page=p;const q=new URLSearchParams({auth:$('f_auth').value,modded:$('f_mod').value,search:$('f_q').value,limit,offset:(page-1)*limit});
 fetch('/api/servers?'+q).then(r=>r.json()).then(d=>{
  total=d.total||0;$('pg').textContent=page+' / '+Math.max(1,Math.ceil(total/limit));
  $('rows').innerHTML=d.items.map(s=>'<tr><td>'+esc(s.ip)+':'+s.port+'</td><td>'+tag(s.auth)+'</td><td>'+esc(s.version)+'</td><td class="motd" title="'+esc(s.motd)+'">'+esc(s.motd)+'</td><td>'+s.players_online+'/'+s.players_max+'</td><td>'+s.ping_ms+'ms</td><td>'+esc((s.last_updated||'').slice(5,16))+'</td></tr>').join('')||'<tr><td colspan=7>暂无数据</td></tr>';
 });
}
function refreshCards(){fetch('/api/stats').then(r=>r.json()).then(s=>{
 const auth=s.by_auth||{};
 $('sub').textContent='共发现 '+s.total+' 台服务器，'+s.online_servers+' 台有人在线';
 $('cards').innerHTML=
  '<div class="card"><div class="n">'+s.total+'</div><div class="l">服务器总数</div></div>'+
  '<div class="card"><div class="n" style="color:#52C41A">'+(auth.cracked||0)+'</div><div class="l">破解(离线)</div></div>'+
  '<div class="card"><div class="n" style="color:#1677FF">'+(auth.online||0)+'</div><div class="l">正版验证</div></div>'+
  '<div class="card"><div class="n" style="color:#FAAD14">'+(auth.whitelist||0)+'</div><div class="l">白名单</div></div>';
});}
function prev(){if(page>1)load(page-1)} function next(){load(page+1)}
setInterval(refreshCards,5000);refreshCards();load(1);
</script></div></body></html>"""


def _serve_servers(handler, params):
    auth = params.get("auth") or None
    mod = params.get("modded")
    mod = None if mod in ("", None) else (mod == "1")
    search = params.get("search") or None
    limit = min(int(params.get("limit", 50)), 500)
    offset = int(params.get("offset", 0))
    rows = db.query(handler.server.db_path, auth=auth, modded=mod, search=search,
                    limit=limit, offset=offset)
    total = len(rows)
    return {"total": total, "items": rows}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send_json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        params = {k: v[0] for k, v in params.items()}
        try:
            if parsed.path == "/" or parsed.path == "/index.html":
                body = PAGE_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif parsed.path == "/api/stats":
                self._send_json(db.stats(self.server.db_path))
            elif parsed.path == "/api/servers":
                self._send_json(_serve_servers(self, params))
            else:
                self.send_error(404)
        except Exception as e:
            self._send_json({"error": str(e)})


def run(db_path="servers.db", host="0.0.0.0", port=8080):
    db.init_db(db_path)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.db_path = db_path
    print(f"[*] Web 面板: http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = sys.argv[1:]
    port = 8080
    db_path = "servers.db"
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    if "--db" in args:
        db_path = args[args.index("--db") + 1]
    run(db_path, port=port)
