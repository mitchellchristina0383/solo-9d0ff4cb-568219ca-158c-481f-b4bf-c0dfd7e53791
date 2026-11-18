"""Unit tests for the HMAC signed admission layer.

Run:  python3 -I tests/test_signed_auth.py
(also runnable with pytest)
"""

import os
import sqlite3
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.signed_auth import (  # noqa: E402
    AdmissionLedger,
    Authenticator,
    AuthError,
    canonical_string,
    load_clients,
    raw_path_with_query,
    sign,
)

CLIENTS = {"demo-client": "demo-secret", "other": "other-secret"}


def hdrs(client="demo-client", secret="demo-secret", ts=None, nonce=None,
         method="GET", target="/proxy", sig=None):
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or ("n" + os.urandom(12).hex())
    signature = sig if sig is not None else sign(secret, client, ts, nonce, method, target)
    return {
        "x-client-id": client,
        "x-timestamp": str(ts),
        "x-nonce": nonce,
        "x-signature": signature,
    }


def make_auth(tmpdir, clock=time.time, **kw):
    db = os.path.join(tmpdir, "ledger.db")
    ledger = AdmissionLedger(db, clock=clock)
    return Authenticator(ledger, CLIENTS, clock=clock, **kw), db


def expect_error(fn, reason):
    try:
        fn()
    except AuthError as exc:
        assert exc.reason == reason, (exc.reason, reason)
        return exc
    raise AssertionError(f"expected AuthError({reason})")


def test_sign_matches_documented_vectors():
    # Known-answer style: canonical format is stable.
    assert canonical_string("c", 123, "nonce", "get", "/proxy?x=1") == (
        "v1\nc\n123\nnonce\nGET\n/proxy?x=1"
    )
    assert sign("k", "c", 123, "nonce", "GET", "/proxy") == sign(
        "k", "c", "123", "nonce", "get", "/proxy"
    )
    assert len(sign("k", "c", 123, "nonce", "GET", "/proxy")) == 64


def test_raw_path_with_query_preserves_percent_encoding():
    scope = {
        "path": "/proxy/x y",
        "raw_path": b"/proxy/x%20y",
        "query_string": b"a=1&b=%E4%B8%AD",
    }
    assert raw_path_with_query(scope) == "/proxy/x%20y?a=1&b=%E4%B8%AD"
    assert raw_path_with_query({"path": "/proxy", "query_string": b""}) == "/proxy"


def test_valid_signature_is_admitted_once():
    t = tempfile.mkdtemp()
    auth, _ = make_auth(t)
    h = hdrs(nonce="nonce-aaaaaaaa")
    r = auth.verify_and_admit(h, "GET", "/proxy")
    assert r.client_id == "demo-client" and r.nonce == "nonce-aaaaaaaa"
    # exact same signed request again -> replay
    expect_error(lambda: auth.verify_and_admit(h, "GET", "/proxy"), "replay_detected")


def test_signature_covers_method_and_target():
    t = tempfile.mkdtemp()
    auth, _ = make_auth(t)
    h = hdrs(nonce="nonce-bbbbbbbb", target="/proxy")
    expect_error(lambda: auth.verify_and_admit(h, "GET", "/proxy?x=1"), "invalid_signature")
    h2 = hdrs(nonce="nonce-cccccccc", method="POST", target="/proxy")
    expect_error(lambda: auth.verify_and_admit(h2, "GET", "/proxy"), "invalid_signature")


def test_wrong_secret_and_tampered_signature_rejected():
    t = tempfile.mkdtemp()
    auth, _ = make_auth(t)
    bad = hdrs(secret="wrong", nonce="nonce-dddddddd")
    expect_error(lambda: auth.verify_and_admit(bad, "GET", "/proxy"), "invalid_signature")
    good = hdrs(nonce="nonce-eeeeeeee")
    good["x-signature"] = ("0" if good["x-signature"][0] != "0" else "1") + good["x-signature"][1:]
    expect_error(lambda: auth.verify_and_admit(good, "GET", "/proxy"), "invalid_signature")


def test_unknown_client_indistinguishable_and_missing_headers():
    t = tempfile.mkdtemp()
    auth, _ = make_auth(t)
    expect_error(
        lambda: auth.verify({}, "GET", "/proxy"), "signature_required"
    )
    h = hdrs(client="ghost", nonce="nonce-ffffffff")
    # Unknown clients are indistinguishable from a wrong secret.
    expect_error(lambda: auth.verify_and_admit(h, "GET", "/proxy"), "invalid_signature")


def test_timestamp_skew_rejected_both_directions():
    t = tempfile.mkdtemp()
    now = 1_700_000_000.0
    auth, _ = make_auth(t, clock=lambda: now)
    old = hdrs(ts=int(now) - 31, nonce="nonce-gggggggg")
    expect_error(lambda: auth.verify_and_admit(old, "GET", "/proxy"), "timestamp_skew")
    future = hdrs(ts=int(now) + 31, nonce="nonce-hhhhhhhh")
    expect_error(lambda: auth.verify_and_admit(future, "GET", "/proxy"), "timestamp_skew")
    # exactly at the boundary is accepted (30s window)
    edge = hdrs(ts=int(now) - 30, nonce="nonce-iiiiiiii")
    assert auth.verify_and_admit(edge, "GET", "/proxy").timestamp == int(now) - 30


def test_skew_rejected_nonce_not_burned():
    # A rejected request must not consume the nonce: once corrected, the
    # client can reuse that nonce in a fresh (in-window) signature.
    t = tempfile.mkdtemp()
    now = 1_700_000_000.0
    auth, db = make_auth(t, clock=lambda: now)
    stale = hdrs(ts=int(now) - 120, nonce="nonce-jjjjjjjj")
    expect_error(lambda: auth.verify_and_admit(stale, "GET", "/proxy"), "timestamp_skew")
    fresh = hdrs(ts=int(now), nonce="nonce-jjjjjjjj")
    assert auth.verify_and_admit(fresh, "GET", "/proxy").nonce == "nonce-jjjjjjjj"


def test_concurrent_same_nonce_only_one_admitted_across_instances():
    t = tempfile.mkdtemp()
    db = os.path.join(t, "ledger.db")
    auths = [
        Authenticator(AdmissionLedger(db), CLIENTS),
        Authenticator(AdmissionLedger(db), CLIENTS),
    ]
    h = hdrs(nonce="nonce-race0001")
    n = 16
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def worker(i):
        barrier.wait()
        try:
            auths[i % 2].verify_and_admit(h, "GET", "/proxy")
            outcome = "admitted"
        except AuthError as exc:
            outcome = exc.reason
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert results.count("admitted") == 1, results
    assert results.count("replay_detected") == n - 1, results


def test_concurrent_distinct_nonces_all_admitted():
    t = tempfile.mkdtemp()
    db = os.path.join(t, "ledger.db")
    auths = [Authenticator(AdmissionLedger(db), CLIENTS) for _ in range(2)]
    n = 20
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def worker(i):
        barrier.wait()
        h = hdrs(nonce=f"nonce-distinct-{i:04d}")
        try:
            auths[i % 2].verify_and_admit(h, "GET", "/proxy")
            outcome = "admitted"
        except AuthError as exc:
            outcome = exc.reason
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert results.count("admitted") == n, results


def test_unwritable_ledger_fails_closed():
    t = tempfile.mkdtemp()
    ro = os.path.join(t, "readonly")
    os.makedirs(ro)
    ledger = AdmissionLedger(os.path.join(ro, "ledger.db"))
    auth = Authenticator(ledger, CLIENTS)
    # Create the DB then make the directory read-only (POSIX).
    ledger.admit(
        auth.verify(hdrs(nonce="nonce-warm00000"), "GET", "/proxy")
    )
    os.chmod(ro, 0o500)
    try:
        h = hdrs(nonce="nonce-blocked001")
        exc = expect_error(
            lambda: auth.verify_and_admit(h, "GET", "/proxy"),
            "admission_ledger_unavailable",
        )
        assert exc.status_code == 503
    finally:
        os.chmod(ro, 0o700)


def test_ledger_db_unopenable_fails_closed():
    t = tempfile.mkdtemp()
    missing = os.path.join(t, "no-such-dir", "ledger.db")
    auth = Authenticator(AdmissionLedger(missing), CLIENTS)
    exc = expect_error(
        lambda: auth.verify_and_admit(hdrs(nonce="nonce-nodir0001"), "GET", "/proxy"),
        "admission_ledger_unavailable",
    )
    assert exc.status_code == 503


def test_duplicate_is_per_client():
    t = tempfile.mkdtemp()
    auth, _ = make_auth(t)
    h1 = hdrs(client="demo-client", secret="demo-secret", nonce="nonce-shared01")
    h2 = hdrs(client="other", secret="other-secret", nonce="nonce-shared01")
    auth.verify_and_admit(h1, "GET", "/proxy")
    auth.verify_and_admit(h2, "GET", "/proxy")
    expect_error(lambda: auth.verify_and_admit(h1, "GET", "/proxy"), "replay_detected")


def test_ledger_prunes_old_rows():
    t = tempfile.mkdtemp()
    clock_t = [1000.0]
    db = os.path.join(t, "ledger.db")
    auth = Authenticator(
        AdmissionLedger(db, clock=lambda: clock_t[0]), CLIENTS,
        clock=lambda: clock_t[0],
    )
    # Directly insert a stale row to avoid the 30 s skew check.
    conn = sqlite3.connect(db)
    from app.signed_auth import LEDGER_TABLE_SQL, LEDGER_INDEX_SQL
    conn.execute(LEDGER_TABLE_SQL)
    conn.execute(LEDGER_INDEX_SQL)
    conn.execute(
        "INSERT INTO signed_admissions VALUES (?,?,?,?,?,?,?)",
        ("old", "oldnonce", 1, 100.0, "GET", "/proxy", "x"),
    )
    conn.commit()
    conn.close()
    clock_t[0] = 100.0 + 3600 + 1
    auth.verify_and_admit(
        hdrs(ts=int(clock_t[0]), nonce="nonce-prune0001"), "GET", "/proxy"
    )
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT client_id FROM signed_admissions").fetchall()
    conn.close()
    assert ("old",) not in rows


def test_load_clients_formats():
    assert load_clients({"SIGNED_CLIENTS": '{"a":"1","b":"2"}'}) == {"a": "1", "b": "2"}
    assert load_clients({"SIGNED_CLIENTS": "not json", "SIGNED_CLIENT_ID": "x",
                         "SIGNED_CLIENT_SECRET": "y"}) == {}
    assert load_clients({"SIGNED_CLIENT_ID": "x", "SIGNED_CLIENT_SECRET": "y"}) == {"x": "y"}


def _run_all():
    import inspect
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and inspect.isfunction(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
        passed += 1
    print(f"\n{passed} tests passed")


if __name__ == "__main__":
    _run_all()
