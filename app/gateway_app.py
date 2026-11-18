"""Circuit-breaker gateway.

Forwards GET requests to the flaky upstream through a shared SQLite-backed
breaker.  Two instances run behind no load balancer: the web UI talks to each
entry point directly (ports 8001 / 8002) so either instance can be driven.

``GET /proxy`` is the only upstream-facing entry and requires an HMAC
signature (``X-Client-Id`` / ``X-Timestamp`` / ``X-Nonce`` / ``X-Signature``,
secret never sent).  A single-use nonce ledger lives in the same shared SQLite
file for both gateway instances.

Signed requests are rejected *before* ``Breaker.dispatch()`` and before any
upstream I/O when the signature is missing/invalid, the clock is off by more
than 30 s, the nonce was already used, or the shared ledger cannot be written.
Such a request can therefore neither consume upstream capacity, count as a
breaker failure, nor occupy the single HALF_OPEN recovery-probe slot.

Once admitted, a request is processed under the normal breaker rules no matter
how long it takes; the 30 s window is an admission check only.

See ``app/signed_auth.py`` for the canonical string and replay semantics.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .breaker import Breaker
from .signed_auth import (
    SIGNATURE_VERSION,
    AdmissionLedger,
    AuthError,
    Authenticator,
    raw_path_with_query,
)

INSTANCE_ID = os.getenv("INSTANCE_ID") or f"gw-{socket.gethostname()}"
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://upstream:8000")
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "2"))
DB_PATH = os.getenv("CB_DB_PATH", "/data/breaker.db")

# The nonce ledger lives in the same shared SQLite file by default, which is
# what makes "same nonce concurrently sent to both gateways" a single atomic
# INSERT ... PRIMARY KEY race rather than a per-instance check.
SIGNED_LEDGER_PATH = os.getenv("SIGNED_LEDGER_PATH", DB_PATH)

breaker = Breaker(DB_PATH, INSTANCE_ID)
ledger = AdmissionLedger(SIGNED_LEDGER_PATH)
authenticator = Authenticator(ledger)
_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    # Best effort: create the shared ledger table up front so the first signed
    # request does not race both gateways through CREATE TABLE.  If this fails
    # (e.g. the volume is read-only) the gateway still starts; every signed
    # admission will then fail closed with admission_ledger_unavailable.
    ledger_status = ledger.ensure_ready()
    # uvicorn configures the root logger; its "uvicorn.error" logger has
    # handlers attached and is the reliable place for startup diagnostics.
    log = logging.getLogger("uvicorn.error")
    if ledger_status == "ready":
        log.info("admission ledger ready at %s", SIGNED_LEDGER_PATH)
    else:
        log.warning(
            "admission ledger at %s is unavailable; signed /proxy requests "
            "will be rejected (503 admission_ledger_unavailable)",
            SIGNED_LEDGER_PATH,
        )
    if not authenticator.clients:
        log.warning(
            "no signing clients configured (SIGNED_CLIENTS); every /proxy "
            "request will be rejected as invalid_signature"
        )
    elif "demo-secret-please-change" in authenticator.clients.values():
        log.warning("demo signing secret in use; set SIGNED_CLIENTS in production")
    _client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT)
    yield
    await _client.aclose()


app = FastAPI(title=f"breaker-gateway ({INSTANCE_ID})", version="1.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok", "instance": INSTANCE_ID}


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


@app.get("/api/state")
async def api_state():
    return {
        "instance": INSTANCE_ID,
        "upstream_url": UPSTREAM_URL,
        "upstream_timeout": UPSTREAM_TIMEOUT,
        "breaker": breaker.get_state(),
    }


@app.get("/api/events")
async def api_events(limit: int = 30):
    return {"instance": INSTANCE_ID, "events": breaker.get_events(limit)}


@app.post("/api/upstream/mode")
async def api_set_mode(request: Request):
    """Convenience: switch upstream mode through this gateway entry point."""
    body = await request.body()
    try:
        r = await _client.post(f"{UPSTREAM_URL}/mode", content=body,
                               headers={"content-type": "application/json"})
        return JSONResponse(status_code=r.status_code, content=r.json())
    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": f"cannot reach upstream to switch mode: {exc!r}"},
        )


@app.get("/api/config")
async def api_config():
    """Public, non-secret configuration for the browser test console."""
    client = next(iter(authenticator.clients), "")
    return {
        "instance": INSTANCE_ID,
        "signature_version": SIGNATURE_VERSION,
        "signed_endpoint": "/proxy",
        "canonical_example": "v1\n<client-id>\n<timestamp>\n<nonce>\nGET\n<raw path + query>",
        "signed_headers": {
            "client_id": "X-Client-Id",
            "timestamp": "X-Timestamp",
            "nonce": "X-Nonce",
            "signature": "X-Signature",
        },
        "max_skew_seconds": authenticator.max_skew_seconds,
        "demo_client_id": client,
    }


@app.get("/api/upstream/mode")
async def api_get_mode():
    try:
        r = await _client.get(f"{UPSTREAM_URL}/mode")
        return r.json()
    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": f"upstream unreachable: {exc!r}", "reachable": False}
        )


@app.get("/proxy")
async def proxy(request: Request):
    """The guarded, HMAC-signed GET path.

    Order matters: signature + timestamp + single-use nonce are all validated
    before ``breaker.dispatch()`` and before any upstream I/O.  A rejected
    request therefore cannot take the recovery-probe slot or count as a
    failure/success for the breaker.  Once admitted, the request runs to
    completion under the normal breaker rules regardless of how long it takes
    (the 30 s timestamp window is an admission check only).
    """
    raw_target = raw_path_with_query(request.scope)
    try:
        # verify() checks the timestamp window and the HMAC; admit() burns the
        # nonce in the shared ledger.  Both happen before breaker.dispatch()
        # and before any upstream I/O.  Any failure -> reject here.  The ledger
        # call is synchronous SQLite (with a busy timeout); run it off the event
        # loop so contention on the shared file cannot stall other requests.
        signed = await asyncio.to_thread(
            authenticator.verify_and_admit,
            request.headers,
            request.method,
            raw_target,
        )
    except AuthError as exc:
        # Echo the claimed client id only for operator convenience; cap it so
        # an oversized header cannot be reflected back at the caller.
        claimed = (request.headers.get("x-client-id") or "")[:128]
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "gateway": INSTANCE_ID,
                "client_id": claimed,
                **exc.as_dict(),
            },
        )
    return await _guarded_forward(client_id=signed.client_id)


async def _guarded_forward(client_id: str | None = None):
    """Breaker + upstream path, reached only after a signed admission."""
    decision = breaker.dispatch()

    if decision["action"] == "reject":
        return JSONResponse(
            status_code=503,
            content={
                "gateway": INSTANCE_ID,
                "client_id": client_id,
                "rejected": True,
                "reason": decision["reason"],
                "decision": decision,
                "breaker": breaker.get_state(),
            },
        )

    # Forward (normal request or the single recovery probe).
    try:
        r = await _client.get(UPSTREAM_URL + "/")
    except httpx.TimeoutException:
        new_state = breaker.record_failure(decision, "timeout")
        return JSONResponse(
            status_code=504,
            content={
                "gateway": INSTANCE_ID,
                "client_id": client_id,
                "outcome": "timeout",
                "applied": new_state is not None,
                "breaker": new_state or breaker.get_state(),
            },
        )
    except httpx.HTTPError as exc:
        new_state = breaker.record_failure(decision, f"connection_error:{type(exc).__name__}")
        return JSONResponse(
            status_code=502,
            content={
                "gateway": INSTANCE_ID,
                "client_id": client_id,
                "outcome": "connection_error",
                "detail": repr(exc),
                "applied": new_state is not None,
                "breaker": new_state or breaker.get_state(),
            },
        )

    if r.status_code >= 500:
        new_state = breaker.record_failure(decision, f"http_{r.status_code}")
        return JSONResponse(
            status_code=r.status_code,
            content={
                "gateway": INSTANCE_ID,
                "client_id": client_id,
                "outcome": "upstream_5xx",
                "upstream_body": _safe_json(r),
                "applied": new_state is not None,
                "breaker": new_state or breaker.get_state(),
            },
        )

    new_state = breaker.record_success(decision)
    return JSONResponse(
        status_code=r.status_code,
        content={
            "gateway": INSTANCE_ID,
            "client_id": client_id,
            "outcome": "success",
            "upstream_body": _safe_json(r),
            "applied": new_state is not None,
            "breaker": new_state or breaker.get_state(),
        },
    )


def _safe_json(r: httpx.Response):
    try:
        return r.json()
    except Exception:
        return r.text


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>熔断网关控制台</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, "Segoe UI", sans-serif; margin: 0; padding: 1.2rem;
         background: #0f1115; color: #e6e6e6; }
  h1 { font-size: 1.25rem; margin: 0 0 .8rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .card { background: #181b22; border: 1px solid #2a2f3a; border-radius: 10px;
          padding: 1rem; }
  .card h2 { font-size: .95rem; margin: 0 0 .6rem; color: #9fb4ff; }
  button { border: 0; border-radius: 8px; padding: .5rem .8rem; margin: .2rem .2rem .2rem 0;
           cursor: pointer; font-weight: 600; }
  button.go { background: #2f81f7; color: #fff; }
  button.mode { background: #30363d; color: #e6e6e6; }
  button.mode.active { background: #238636; }
  button:disabled { opacity: .45; cursor: default; }
  pre { background: #0d1117; border: 1px solid #2a2f3a; border-radius: 8px;
        padding: .7rem; overflow:auto; max-height: 320px; font-size: .78rem; }
  .pill { display:inline-block; padding: .15rem .55rem; border-radius: 999px;
          font-size: .78rem; font-weight: 700; }
  .CLOSED { background:#1a7f37; color:#fff; }
  .OPEN { background:#da3633; color:#fff; }
  .HALF_OPEN { background:#9e6a03; color:#fff; }
  table { width:100%; border-collapse: collapse; font-size: .78rem; }
  th, td { text-align:left; padding: .25rem .35rem; border-bottom:1px solid #2a2f3a;
           vertical-align: top; }
  .muted { color:#8b949e; font-size:.78rem; }
  .row { display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; }
  input { background:#0d1117; border:1px solid #2a2f3a; color:#e6e6e6;
          border-radius:8px; padding:.45rem .6rem; width: 14rem; }
  #secret { width: 18rem; }
  #query { width: 12rem; }
</style>
</head>
<body>
<h1>熔断网关控制台 <span class="muted" id="who"></span></h1>
<div class="grid">
  <div class="card">
    <h2>1. 选择网关入口</h2>
    <div class="row">
      <label class="muted">入口地址</label>
      <input id="base" value="">
      <button class="go" onclick="saveBase()">保存</button>
    </div>
    <p class="muted">两台网关共享同一份 SQLite 熔断状态，任选其一操作即可；
       也可分别打开两个浏览器标签指向 8001 / 8002 观察联动。</p>
  </div>

  <div class="card">
    <h2>2. 上游模式（任一台网关切换均生效）</h2>
    <div class="row">
      <button class="mode" onclick="setMode('normal')">正常 normal</button>
      <button class="mode" onclick="setMode('slow')">慢响应 slow（5s）</button>
      <button class="mode" onclick="setMode('error')">500 错误 error</button>
    </div>
    <p class="muted" id="upmode"></p>
  </div>

  <div class="card">
    <h2>3. 发送 GET（签名入口，经熔断转发）</h2>
    <div class="row">
      <button class="go" onclick="send(1)">发 1 笔</button>
      <button class="go" onclick="send(3)">连发 3 笔</button>
      <button class="go" onclick="send(5)">连发 5 笔</button>
      <button class="go" onclick="send(10)">并发 10 笔</button>
    </div>
    <p class="muted">以上按钮走签名入口（每次自动生成新随机数）。</p>
    <pre id="result">（结果显示在这里）</pre>
  </div>

  <div class="card">
    <h2>4. 签名请求（HMAC-SHA256）</h2>
    <div class="row">
      <label class="muted">客户端标识</label>
      <input id="clientId" value="">
    </div>
    <div class="row" style="margin-top:.4rem">
      <label class="muted">密钥（仅本地计算，不随请求发送）</label>
      <input id="secret" type="password" autocomplete="off" placeholder="本地演示客户端密钥">
    </div>
    <div class="row" style="margin-top:.4rem">
      <label class="muted">查询串（参与签名）</label>
      <input id="query" value="" placeholder="?demo=1">
    </div>
    <div class="row" style="margin-top:.5rem">
      <button class="go" onclick="sendSigned()">发签名 GET</button>
      <button class="mode" onclick="resend()">重发原签名</button>
      <button class="mode" onclick="concurrentReplay(8)">并发重放原签名 ×8</button>
      <button class="mode" onclick="sendTampered()">篡改签名</button>
      <button class="mode" onclick="sendSkewed()">时间戳 -60s</button>
    </div>
    <p class="muted">签名覆盖：版本、客户端标识、时间戳、随机数、请求方法、原始路径与查询串。
       重发与并发重放都复用同一随机数，应被共享受理记录拒绝（409）。</p>
    <pre id="signedResult">（签名请求结果显示在这里）</pre>
  </div>

  <div class="card">
    <h2>5. 熔断状态 <span id="statepill"></span></h2>
    <pre id="state"></pre>
    <h2 style="margin-top:.8rem">事件流（两台实例共享）</h2>
    <table><thead><tr><th>#</th><th>距今(s)</th><th>实例</th><th>事件</th><th>详情</th></tr></thead>
    <tbody id="events"></tbody></table>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);
function defaultBase() {
  return location.origin || `http://${location.hostname}:8001`;
}
$("base").value = localStorage.getItem("gwBase") || defaultBase();
function saveBase() { localStorage.setItem("gwBase", $("base").value); refresh(); }
const base = () => $("base").value.replace(/\\/$/, "");

async function api(path, opts) {
  const r = await fetch(base() + path, opts);
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: r.status, body };
}

async function setMode(m) {
  const { status, body } = await api("/api/upstream/mode", {
    method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({mode: m})
  });
  $("result").textContent = `切换模式 -> ${m}\\nHTTP ${status}\\n` + JSON.stringify(body, null, 2);
  refresh();
}

async function sendOne() {
  try { return await signedCall(await makeSigned()); }
  catch (e) { return { status: 0, body: { error: String(e) } }; }
}
async function send(n) {
  const parallel = n >= 10;
  let outcomes;
  if (parallel) outcomes = await Promise.all(Array.from({length: n}, sendOne));
  else {
    outcomes = [];
    for (let i = 0; i < n; i++) outcomes.push(await sendOne());
  }
  $("result").textContent = outcomes.map((o, i) =>
    `#${i+1} HTTP ${o.status}: ` + JSON.stringify(o.body)).join("\\n\\n");
  refresh();
}

// ---- signed entry -------------------------------------------------------
const enc = new TextEncoder();
let lastSigned = null;

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function rawTarget() {
  // Sign the same percent-encoded path+query the browser sends.  The query
  // field is pasted verbatim (including a leading "?"); the gateway signs the
  // ASGI raw_path + "?" + raw query_string.
  const q = $("query").value.trim();
  return "/proxy" + (q ? (q.startsWith("?") ? q : "?" + q) : "");
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, "0")).join("");
}

async function makeSigned(opts = {}) {
  const clientId = opts.clientId || $("clientId").value.trim();
  const secret = opts.secret != null ? opts.secret : $("secret").value;
  const ts = opts.timestamp != null ? opts.timestamp : Math.floor(Date.now() / 1000);
  const nonce = opts.nonce || randomNonce();
  const target = opts.target || rawTarget();
  const canonical = ["v1", clientId, String(ts), nonce, "GET", target].join("\\n");
  let signature;
  if (opts.badSignature) {
    signature = (await hmacHex(secret, canonical)).replace(/^./, c => c === "0" ? "1" : "0");
  } else {
    signature = await hmacHex(secret, canonical);
  }
  return {clientId, ts, nonce, target, signature, canonical};
}

async function signedCall(s) {
  const headers = {
    "X-Client-Id": s.clientId,
    "X-Timestamp": String(s.ts),
    "X-Nonce": s.nonce,
    "X-Signature": s.signature,
  };
  const r = await fetch(base() + s.target, {headers});
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return {status: r.status, body, signed: s};
}

function showSigned(label, result) {
  const s = result.signed || {};
  $("signedResult").textContent =
    `${label}\\nHTTP ${result.status}\\n签名请求头: X-Client-Id=${s.clientId} ` +
    `X-Timestamp=${s.ts} X-Nonce=${s.nonce}\\n` +
    `请求目标: ${s.target}\\n\\n` + JSON.stringify(result.body, null, 2);
}

async function sendSigned() {
  lastSigned = await makeSigned();
  showSigned("新签名请求（新随机数）", await signedCall(lastSigned));
  refresh();
}

async function resend() {
  if (!lastSigned) { $("signedResult").textContent = "还没有已签名请求，请先发送一笔。"; return; }
  showSigned("重发原签名（同一随机数，应 409）", await signedCall(lastSigned));
  refresh();
}

async function concurrentReplay(n) {
  if (!lastSigned) { $("signedResult").textContent = "还没有已签名请求，请先发送一笔。"; return; }
  const s = lastSigned;
  const results = await Promise.all(Array.from({length: n}, () => signedCall(s)));
  const accepted = results.filter(r => r.status !== 409).length;
  const replayed = results.filter(r => r.status === 409).length;
  const summary = results.map((r, i) => `#${i+1} HTTP ${r.status} ` +
    JSON.stringify(r.body && r.body.reason ? {reason: r.body.reason} : r.body)).join("\\n");
  $("signedResult").textContent =
    `并发重放原签名 ×${n}（同一随机数）\\n` + summary +
    `\\n\\n仅首次放行: ${accepted === 1 ? "是" : "否"}（非 409 计 ${accepted} 笔，` +
    `重复拒绝 ${replayed} 笔）`;
  refresh();
}

async function sendTampered() {
  const s = await makeSigned({badSignature: true});
  showSigned("篡改签名（应 401 invalid_signature）", await signedCall(s));
  refresh();
}

async function sendSkewed() {
  const s = await makeSigned({timestamp: Math.floor(Date.now() / 1000) - 60});
  showSigned("时间戳偏移 -60s（应 401 timestamp_skew）", await signedCall(s));
  refresh();
}

async function loadConfig() {
  try {
    const {body: cfg} = await api("/api/config");
    if (!$("clientId").value) $("clientId").value = cfg.demo_client_id || "";
    // The secret is never fetched from the server and never persisted: it
    // lives only in this input for the duration of the page.
    $("secret").placeholder = "演示密钥见 README / SIGNED_CLIENTS";
  } catch (e) { /* ignore */ }
}
loadConfig();

async function refresh() {
  try {
    const [{body: st}, {body: ev}, up] = await Promise.all([
      api("/api/state"), api("/api/events?limit=20"),
      api("/api/upstream/mode").catch(e => ({body: {error: String(e)}}))
    ]);
    $("who").textContent = "当前入口实例: " + st.instance;
    const b = st.breaker;
    $("statepill").innerHTML =
      `<span class="pill ${b.state}">${b.state}</span>`;
    $("state").textContent = JSON.stringify({
      state: b.state,
      failure_count: b.failure_count,
      threshold: b.failure_threshold,
      epoch: b.epoch,
      cooldown_remaining_s: b.cooldown_remaining,
      probe_instance: b.probe_instance,
      probe_age_s: b.probe_started_at != null
        ? Number((b.now - b.probe_started_at).toFixed(3)) : null
    }, null, 2);
    $("events").innerHTML = (ev.events || []).map(e =>
      `<tr><td>${e.id}</td><td>${e.age}</td><td>${e.instance}</td>
       <td>${e.kind}</td><td>${e.detail}</td></tr>`).join("");
    document.querySelectorAll(".mode").forEach(btn => btn.classList.remove("active"));
    if (up && up.mode) {
      $("upmode").textContent = "上游当前模式: " + up.mode + "，累计调用: " + up.calls;
      const map = {normal:0, slow:1, error:2};
      const idx = map[up.mode];
      if (idx != null) document.querySelectorAll(".mode")[idx].classList.add("active");
    } else {
      $("upmode").textContent = "上游不可达（失联）: " + JSON.stringify(up);
    }
  } catch (e) {
    $("state").textContent = "刷新失败: " + e;
  }
}
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>
"""
