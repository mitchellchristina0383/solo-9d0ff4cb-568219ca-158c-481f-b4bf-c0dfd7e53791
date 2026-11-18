"""In-process ASGI tests: admission-before-dispatch, slow admitted requests and
probe interleaving.

Run:  python3 -I tests/test_gateway_asgi.py
(also runnable with pytest; requires httpx + fastapi, i.e. the app deps)

The gateway module is imported *after* setting its environment, so the breaker
and nonce ledger live in a temporary directory.
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, ".pylibs", "lib", "python3.11", "site-packages"))

_TMP = tempfile.mkdtemp(prefix="gw-asgi-")
os.environ.update({
    "INSTANCE_ID": "gateway-test",
    "UPSTREAM_URL": "http://upstream.invalid",
    "UPSTREAM_TIMEOUT": "2",
    "CB_DB_PATH": os.path.join(_TMP, "breaker.db"),
    "SIGNED_LEDGER_PATH": os.path.join(_TMP, "breaker.db"),
    "CB_FAILURE_THRESHOLD": "3",
    "CB_COOLDOWN_SECONDS": "0.1",
    "CB_PROBE_TIMEOUT_SECONDS": "10",
    "SIGNED_CLIENTS": json.dumps({"demo-client": "demo-secret"}),
    "SIGNED_MAX_SKEW_SECONDS": "1",
    "PYTHONPATH": ROOT,
})

import httpx  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app import gateway_app  # noqa: E402

CLIENT_ID = "demo-client"
SECRET = "demo-secret"


def sign_headers(target="/proxy", ts=None, nonce=None, secret=SECRET,
                 client=CLIENT_ID, method="GET", signature=None):
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or os.urandom(8).hex()
    message = "\n".join(["v1", client, str(ts), nonce, method, target])
    sig = signature or hmac.new(
        secret.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    return {
        "X-Client-Id": client,
        "X-Timestamp": str(ts),
        "X-Nonce": nonce,
        "X-Signature": sig,
    }


class FakeUpstream:
    """Minimal stand-in for httpx.AsyncClient used by the gateway."""

    def __init__(self, status=200, delay=0.0):
        self.status = status
        self.delay = delay
        self.calls = 0

    async def get(self, url):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        return httpx.Response(self.status, json={"upstream": "fake"})


def asgi_client():
    transport = ASGITransport(app=gateway_app.app)
    return AsyncClient(transport=transport, base_url="http://gw.test")


def run(coro):
    return asyncio.run(coro)


def reset_breaker():
    gateway_app.breaker._init_db()
    import sqlite3
    conn = sqlite3.connect(os.environ["CB_DB_PATH"])
    conn.execute(
        "UPDATE breaker_state SET state='CLOSED', failure_count=0, epoch=epoch+1,"
        " opened_at=NULL, probe_token=NULL, probe_instance=NULL,"
        " probe_started_at=NULL WHERE id=1"
    )
    conn.commit()
    conn.close()


def trip_breaker():
    reset_breaker()
    for _ in range(3):
        d = gateway_app.breaker.dispatch()
        gateway_app.breaker.record_failure(d, "test_trip")


PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def test_unsigned_rejected_before_breaker():
    reset_breaker()
    gateway_app._client = FakeUpstream()
    before_calls = gateway_app._client.calls

    async def go():
        async with asgi_client() as c:
            r = await c.get("/proxy")
            return r

    r = run(go())
    check("unsigned -> 401", r.status_code == 401, r.text)
    check("unsigned reason", r.json().get("reason") == "signature_required", r.text)
    check("unsigned did not call upstream", gateway_app._client.calls == before_calls)
    st = gateway_app.breaker.get_state()
    check("unsigned did not touch breaker",
          st["state"] == "CLOSED" and st["failure_count"] == 0, str(st))


def test_replay_rejected_before_breaker():
    reset_breaker()
    gateway_app._client = FakeUpstream()
    h = sign_headers(nonce="asgi-replay-0001")

    async def go():
        async with asgi_client() as c:
            first = await c.get("/proxy", headers=h)
            second = await c.get("/proxy", headers=h)
            return first, second

    first, second = run(go())
    check("first signed use -> 200", first.status_code == 200, first.text)
    check("second identical use -> 409", second.status_code == 409, second.text)
    check("replay reason", second.json().get("reason") == "replay_detected", second.text)
    check("replay did not call upstream", gateway_app._client.calls == 1,
          str(gateway_app._client.calls))


def test_admitted_request_completes_after_skew_window():
    """Admission is checked once; processing beyond the skew window still
    completes and applies its result under normal breaker rules."""
    reset_breaker()
    # Upstream takes 1.4s; skew window is 1s.  The timestamp is valid at
    # admission and stale by the time the response is recorded.
    upstream = FakeUpstream(delay=1.4)
    gateway_app._client = upstream
    ts = int(time.time())
    h = sign_headers(ts=ts, nonce="asgi-slow-000001")

    async def go():
        async with asgi_client() as c:
            r = await c.get("/proxy", headers=h)
            # a *new* request carrying the same old timestamp is now stale
            stale = sign_headers(ts=ts, nonce="asgi-slow-000002")
            r2 = await c.get("/proxy", headers=stale)
            return r, r2

    started = time.time()
    r, r2 = run(go())
    elapsed = time.time() - started
    check("slow admitted request completed with 200", r.status_code == 200, r.text)
    check("slow request really outlived the skew window", elapsed > 1.0, f"{elapsed:.2f}s")
    check("its success was applied to the breaker", r.json().get("outcome") == "success",
          r.text)
    check("a later request with the same stale timestamp is rejected",
          r2.status_code == 401 and r2.json().get("reason") == "timestamp_skew",
          r2.text)


def test_probe_interleaving_with_replays_and_unsigned():
    """Only one admitted signed request may take the recovery-probe slot;
    replayed/unsigned requests are rejected without consuming it."""
    trip_breaker()
    upstream = FakeUpstream(status=200, delay=0.4)  # probe stays in flight
    gateway_app._client = upstream
    time.sleep(0.15)  # let cooldown elapse

    probe_h = sign_headers(nonce="asgi-probe-000001")

    async def go():
        async with asgi_client() as c:
            probe = asyncio.create_task(c.get("/proxy", headers=probe_h))
            await asyncio.sleep(0.1)  # probe is now in flight
            replay = await c.get("/proxy", headers=probe_h)
            unsigned = await c.get("/proxy")
            other = sign_headers(nonce="asgi-probe-000002")
            peer = await c.get("/proxy", headers=other)
            result = await probe
            return result, replay, unsigned, peer

    result, replay, unsigned, peer = run(go())
    check("the single probe was admitted and succeeded", result.status_code == 200, result.text)
    check("probe actually called upstream once", upstream.calls == 1, str(upstream.calls))
    check("replay during probe -> 409", replay.status_code == 409, replay.text)
    check("unsigned during probe -> 401", unsigned.status_code == 401, unsigned.text)
    check("a second distinct signed request is rejected probe_in_flight",
          peer.status_code == 503 and peer.json().get("reason") == "probe_in_flight",
          peer.text)
    check("only the probe reached upstream", upstream.calls == 1, str(upstream.calls))
    st = gateway_app.breaker.get_state()
    check("probe success closed the breaker", st["state"] == "CLOSED", str(st))


def test_ledger_unwritable_denies_without_probe_or_upstream():
    reset_breaker()
    gateway_app._client = FakeUpstream()
    real_admit = gateway_app.ledger.admit
    gateway_app.ledger.admit = lambda request: "unavailable"
    try:
        async def go():
            async with asgi_client() as c:
                return await c.get("/proxy", headers=sign_headers(nonce="asgi-unavail-01"))

        r = run(go())
        check("unwritable ledger -> 503", r.status_code == 503, r.text)
        check("unwritable ledger reason",
              r.json().get("reason") == "admission_ledger_unavailable", r.text)
        check("unwritable ledger did not call upstream",
              gateway_app._client.calls == 0, str(gateway_app._client.calls))
        st = gateway_app.breaker.get_state()
        check("unwritable ledger did not touch breaker",
              st["state"] == "CLOSED" and st["failure_count"] == 0, str(st))
    finally:
        gateway_app.ledger.admit = real_admit


def _run_all():
    import inspect
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and inspect.isfunction(v)]
    for fn in fns:
        print(fn.__name__)
        fn()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(_run_all())
