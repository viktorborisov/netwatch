#!/usr/bin/env python3
"""
netwatch/app.py — Flask-сервис поверх events.jsonl от bpftrace.

Архитектура:
  [host] tracer.sh -> bpftrace -> /opt/netwatch/logs/events.jsonl
  [container] app.py tail-ит этот файл и отдаёт live-дашборд.

Событие (строка JSON):
  {"ts":<ms_uptime>,"type":"net|proc|file","pid":N,"comm":"...","data":{...}}

Важно: ts в файле — это nsecs ядра (время с загрузки), НЕ Unix-время.
Переводим в реальную метку: REALTIME = boot_time + ts/1000.
"""
import json
import os
import time
import threading
from collections import deque
from flask import Flask, Response, jsonify, render_template_string

EVENTS = os.environ.get("EVENTS_FILE", "/data/events.jsonl")
MAXLEN = int(os.environ.get("RING_SIZE", "1000"))

app = Flask(__name__)

# ring-buffer последних событий + счётчики + подписчики SSE
_buf = deque(maxlen=MAXLEN)
_counts = {"net": 0, "proc": 0, "file": 0}
_lock = threading.Lock()
_subscribers = []  # список очередей (deque) для SSE

# Время загрузки системы: realtime - uptime. Нужно, чтобы перевести
# kernel nsecs в человеческое время. Считаем один раз при старте.
_boot_ms = None


def boot_epoch_ms():
    """Приблизительное время загрузки в Unix-ms."""
    global _boot_ms
    if _boot_ms is None:
        with open("/proc/uptime") as f:
            uptime_s = float(f.read().split()[0])
        _boot_ms = int((time.time() - uptime_s) * 1000)
    return _boot_ms


def enrich(ev):
    """Добавляет реальное время (wall_ts) и человекочитаемое поле desc."""
    try:
        ev["wall_ts"] = boot_epoch_ms() + int(ev.get("ts", 0))
    except Exception:
        ev["wall_ts"] = int(time.time() * 1000)
    t = ev.get("type")
    d = ev.get("data") or {}
    if t == "net":
        ev["desc"] = "%s:%s" % (d.get("daddr"), d.get("dport"))
    elif t == "proc":
        ev["desc"] = d.get("file", "")
    elif t == "file":
        ev["desc"] = d.get("file", "")
    return ev


def tail_loop():
    """Следим за events.jsonl и раздаём новые строки подписчикам."""
    f = None
    inode = None
    while True:
        try:
            if not os.path.exists(EVENTS):
                time.sleep(1)
                continue
            st = os.stat(EVENTS)
            # файл пересоздали (tracer перезапустился) -> откроем заново
            if f is None or inode != st.st_ino:
                if f:
                    f.close()
                f = open(EVENTS, "r")
                inode = st.st_ino
                f.seek(0, os.SEEK_END)  # читаем только новое
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            ev = enrich(ev)
            with _lock:
                _buf.append(ev)
                if ev["type"] in _counts:
                    _counts[ev["type"]] += 1
                subs = list(_subscribers)
            for q in subs:
                q.append(ev)
        except Exception:
            time.sleep(0.5)


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/recent")
def api_recent():
    n = int(os.environ.get("RECENT_N", "200"))
    with _lock:
        evs = list(_buf)[-n:]
        counts = dict(_counts)
    return jsonify({"counts": counts, "events": evs})


@app.route("/events")
def events_sse():
    """Server-Sent Events: пушим каждое новое событие в браузер."""
    def gen():
        q = deque(maxlen=500)
        with _lock:
            _subscribers.append(q)
        try:
            # начальный снимок
            with _lock:
                snapshot = list(_buf)[-100:]
            for ev in snapshot:
                yield f"data: {json.dumps(ev)}\n\n"
            while True:
                if q:
                    ev = q.popleft()
                    yield f"data: {json.dumps(ev)}\n\n"
                else:
                    time.sleep(0.2)
                    yield ": keepalive\n\n"
        finally:
            with _lock:
                if q in _subscribers:
                    _subscribers.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


INDEX_HTML = r"""
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netwatch — eBPF live</title>
<style>
  :root { --bg:#0b0f14; --panel:#111823; --line:#1e2a3a; --fg:#d7e2ee;
          --net:#4cc9f0; --proc:#f4a261; --file:#a06cd5; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; }
  header { padding:12px 16px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
  h1 { font-size:15px; margin:0; letter-spacing:.5px; }
  .pill { padding:2px 10px; border-radius:20px; border:1px solid var(--line);
          font-size:12px; }
  .n { color:#000; background:var(--net); border-color:var(--net); }
  .p { color:#000; background:var(--proc); border-color:var(--proc); }
  .f { color:#000; background:var(--file); border-color:var(--file); }
  .dot { width:8px;height:8px;border-radius:50%;background:#37d67a;
         display:inline-block; animation:pulse 1.4s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
  main { display:grid; grid-template-columns:1fr; height:calc(100vh - 52px); }
  table { border-collapse:collapse; width:100%; }
  thead th { position:sticky; top:0; background:var(--panel);
             text-align:left; padding:7px 12px; border-bottom:1px solid var(--line);
             font-weight:600; color:#8fa3b8; }
  tbody td { padding:5px 12px; border-bottom:1px solid #121b26;
             white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  tbody tr:hover { background:#0f1720; }
  .t-net{color:var(--net)} .t-proc{color:var(--proc)} .t-file{color:var(--file)}
  .wrap { overflow:auto; }
  td.desc { max-width:60ch; }
  .new { animation:flash .8s ease-out; }
  @keyframes flash { from{background:#1b2b3d} to{background:transparent} }
  .filter { background:#0b0f14; color:var(--fg); border:1px solid var(--line);
            border-radius:6px; padding:4px 8px; font:inherit; }
</style>
</head>
<body>
<header>
  <h1>netwatch <span class="dot"></span></h1>
  <span class="filter">фильтр: <input class="filter" id="q" placeholder="type:net / curl / 1.1.1.1"></span>
  <span class="pill n">net <b id="c-net">0</b></span>
  <span class="pill p">proc <b id="c-proc">0</b></span>
  <span class="pill f">file <b id="c-file">0</b></span>
</header>
<main class="wrap">
  <table>
    <thead><tr><th style="width:110px">time</th>
      <th style="width:70px">type</th><th style="width:70px">pid</th>
      <th style="width:140px">comm</th><th>detail</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
</main>
<script>
const MAX = 300;
const rows = document.getElementById("rows");
const q = document.getElementById("q");
let filter = "";
q.addEventListener("input", () => { filter = q.value.trim().toLowerCase(); });

function fmtTime(ms){
  const d = new Date(ms);
  return d.toTimeString().slice(0,8) + "." +
         String(d.getMilliseconds()).padStart(3,"0");
}
function match(ev){
  if(!filter) return true;
  if(filter.startsWith("type:")) return ev.type === filter.slice(5);
  const hay = (ev.type+" "+ev.pid+" "+ev.comm+" "+(ev.desc||"")).toLowerCase();
  return hay.includes(filter);
}
function addRow(ev){
  if(!match(ev)) return;
  const tr = document.createElement("tr");
  tr.className = "new";
  tr.innerHTML =
    `<td>${
fmtTime(ev.wall_ts)}</td>` +
    `<td class="t-${ev.type}">${ev.type}</td>` +
    `<td>${ev.pid}</td>` +
    `<td>${ev.comm||""}</td>` +
    `<td class="desc" title="${(ev.desc||"").replace(/"/g,"&quot;")}">${ev.desc||""}</td>`;
  rows.prepend(tr);
  while(rows.childElementCount > MAX) rows.lastChild.remove();
}
function setCounts(c){
  c = c || {};
  document.getElementById("c-net").textContent = c.net||0;
  document.getElementById("c-proc").textContent = c.proc||0;
  document.getElementById("c-file").textContent = c.file||0;
}

// начальный снимок
fetch("/api/recent").then(r=>r.json()).then(d=>{
  setCounts(d.counts);
  d.events.slice().reverse().forEach(addRow);
});

// live-поток
const es = new EventSource("/events");
es.onmessage = (m)=>{
  if(m.data === "") return;
  const ev = JSON.parse(m.data);
  addRow(ev);
};
es.onerror = ()=>{ /* EventSource сам переподключится */ };
</script>
</body>
</html>
"""


def main():
    threading.Thread(target=tail_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=8000, threaded=True)


if __name__ == "__main__":
    main()
