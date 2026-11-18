"""HMAC-signed admission and a cross-instance nonce ledger.

Why this exists
---------------
``/proxy`` is the only path that may consume upstream capacity and, when the
breaker is ``HALF_OPEN``, the single recovery-probe slot.  An unsigned or
replayed GET must therefore be rejected *before* ``Breaker.dispatch()`` is
called and before any upstream request is made.

Signature scheme (version ``v1``)
---------------------------------
The client holds a secret (never sent on the wire) and four headers::

    X-Client-Id:  <client identifier>
    X-Timestamp:  <integer Unix seconds>
    X-Nonce:      <client-chosen random string>
    X-Signature:  <lowercase hex HMAC-SHA256(secret, canonical)>

The canonical string is UTF-8, newline-separated, with no trailing newline::

    v1
    <client id>
    <timestamp>
    <nonce>
    <METHOD>
    <raw path + "?" + raw query string, exactly as received>

For example a plain signed GET to ``/proxy`` is::

    v1
    demo-client
    1760000000
    4f3c...
    GET
    /proxy

``raw path`` is the percent-encoded request target (``/proxy`` or
``/proxy/anything?x=1``), not the decoded URL and not the upstream URL.

The server checks the timestamp against its own clock.  A skew greater than
``SIGNED_MAX_SKEW_SECONDS`` (default 30) is rejected.  After signature
verification the nonce is inserted into a shared SQLite table with
``PRIMARY KEY (client_id, nonce)``.  The insert runs inside
``BEGIN IMMEDIATE``: concurrent submissions of the same client/nonce across
both gateway processes serialize, exactly one insert succeeds, and the others
are reported as replays.  Every failure to write that shared table is treated
as a rejection too (fail closed), so a read-only/locked ledger cannot be used
to bypass replay protection.

The timestamp is checked *only at admission*.  A request that was admitted and
is still being processed after 30 seconds keeps running; its eventual result is
applied by the normal breaker rules (and may legitimately be ignored as a stale
result if the breaker moved on).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Mapping

SIGNATURE_VERSION = "v1"

HEADER_CLIENT = "x-client-id"
HEADER_TIMESTAMP = "x-timestamp"
HEADER_NONCE = "x-nonce"
HEADER_SIGNATURE = "x-signature"

MAX_SKEW_SECONDS = float(os.getenv("SIGNED_MAX_SKEW_SECONDS", "30"))
NONCE_TTL_SECONDS = float(os.getenv("SIGNED_NONCE_TTL_SECONDS", "3600"))
MAX_CLIENT_LEN = 128
MAX_NONCE_LEN = 200

# Keep the wire format boring: client ids and nonces are opaque token-ish
# strings.  This also prevents NUL/control characters in ledger rows.
_CLIENT_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,%d}$" % MAX_CLIENT_LEN)
_NONCE_RE = re.compile(r"^[A-Za-z0-9._~:/+=-]{1,%d}$" % MAX_NONCE_LEN)

DEMO_CLIENT_ID = os.getenv("SIGNED_CLIENT_ID", "demo-client")
DEMO_CLIENT_SECRET = os.getenv("SIGNED_CLIENT_SECRET", "demo-secret-please-change")


def canonical_string(
    client_id: str,
    timestamp: int | str,
    nonce: str,
    method: str,
    raw_path_query: str,
) -> str:
    """Build the exact bytes-to-be-HMACed, as documented in the module docstring."""
    return "\n".join(
        [
            SIGNATURE_VERSION,
            client_id,
            str(timestamp),
            nonce,
            method.upper(),
            raw_path_query,
        ]
    )


def sign(
    secret: str,
    client_id: str,
    timestamp: int | str,
    nonce: str,
    method: str,
    raw_path_query: str,
) -> str:
    """Convenience helper used by tests and local tooling (lowercase hex)."""
    message = canonical_string(client_id, timestamp, nonce, method, raw_path_query)
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def raw_path_with_query(scope: Mapping[str, Any]) -> str:
    """Return the request target exactly as received (percent-encoding preserved).

    ASGI keeps ``raw_path`` and ``query_string`` as bytes.  Decoding with
    latin-1 is a lossless byte-to-string mapping for the ASCII/percent-encoded
    request target; the browser signs ``URL.pathname + URL.search`` which is the
    same percent-encoded text.
    """
    raw_path = scope.get("raw_path")
    if raw_path is None:
        path = scope.get("path", "/")
    elif isinstance(raw_path, (bytes, bytearray)):
        path = bytes(raw_path).decode("latin-1")
    else:
        path = str(raw_path)
    raw_query = scope.get("query_string", b"")
    if isinstance(raw_query, (bytes, bytearray)):
        query = bytes(raw_query).decode("latin-1")
    else:
        query = str(raw_query)
    return path + (("?" + query) if query else "")


def load_clients(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Load the client-id -> secret mapping.

    Preferred form: ``SIGNED_CLIENTS='{"client-a":"secret-a"}'`` (JSON object).
    Convenience form for the single-client demo: ``SIGNED_CLIENT_ID`` and
    ``SIGNED_CLIENT_SECRET``.  If neither is configured, a documented demo
    client is used; this is deliberately obvious rather than silently open.
    """
    env = os.environ if env is None else env
    raw = env.get("SIGNED_CLIENTS")
    if raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            str(k): str(v)
            for k, v in data.items()
            if isinstance(k, str) and isinstance(v, str) and v
        }
    client_id = env.get("SIGNED_CLIENT_ID", DEMO_CLIENT_ID)
    secret = env.get("SIGNED_CLIENT_SECRET", DEMO_CLIENT_SECRET)
    return {client_id: secret} if client_id and secret else {}


class AuthError(Exception):
    """A request was rejected before it could touch the breaker or upstream."""

    def __init__(self, reason: str, status_code: int = 401, **extra: Any):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code
        self.extra = extra

    def as_dict(self) -> dict[str, Any]:
        out = {"rejected": True, "reason": self.reason}
        out.update(self.extra)
        return out


@dataclass(frozen=True)
class SignedRequest:
    client_id: str
    timestamp: int
    nonce: str
    method: str
    raw_path_query: str
    signature: str


# Statements are executed one-by-one (not executescript) because executescript
# implicitly commits and would break the BEGIN IMMEDIATE admission transaction.
LEDGER_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS signed_admissions ("
    "client_id TEXT NOT NULL,"
    "nonce TEXT NOT NULL,"
    "request_ts INTEGER NOT NULL,"
    "received_at REAL NOT NULL,"
    "method TEXT NOT NULL,"
    "raw_path TEXT NOT NULL,"
    "signature TEXT NOT NULL,"
    "PRIMARY KEY (client_id, nonce))"
)
LEDGER_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS signed_admissions_received_idx "
    "ON signed_admissions (received_at)"
)


class AdmissionLedger:
    """Shared, atomic nonce ledger.

    Returns one of ``"stored"``, ``"duplicate"`` or ``"unavailable"`` from
    :meth:`admit`.  Callers must reject on anything other than ``"stored"``.
    """

    def __init__(
        self,
        db_path: str,
        *,
        clock=time.time,
        ttl_seconds: float = NONCE_TTL_SECONDS,
        busy_timeout_ms: int = 10_000,
    ):
        self.db_path = db_path
        self._clock = clock
        self._ttl_seconds = ttl_seconds
        self._busy_timeout_ms = busy_timeout_ms
        self._schema_ready = False

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, timeout=self._busy_timeout_ms / 1000, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self._busy_timeout_ms)}")
        return conn

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        if self._schema_ready:
            return
        # Autocommit: each DDL statement is atomic on its own.  IF NOT EXISTS
        # makes the concurrent first-use race between the two gateways benign.
        conn.execute(LEDGER_TABLE_SQL)
        conn.execute(LEDGER_INDEX_SQL)
        self._schema_ready = True

    def ensure_ready(self) -> str:
        """Create the schema eagerly (call at process start).

        Returns ``"ready"`` or ``"unavailable"``.  Doing the DDL once at startup
        keeps the per-request admission path to a single BEGIN IMMEDIATE +
        INSERT and avoids two processes racing on CREATE TABLE at first use.
        """
        try:
            conn = self._connect()
        except sqlite3.Error:
            return "unavailable"
        try:
            self._ensure_schema(conn)
            return "ready"
        except sqlite3.Error:
            return "unavailable"
        finally:
            conn.close()

    def admit(self, request: SignedRequest) -> str:
        now = self._clock()
        try:
            conn = self._connect()
        except sqlite3.Error:
            # Cannot open the shared DB at all (missing directory, permissions,
            # read-only mount...).  Fail closed.
            return "unavailable"
        try:
            self._ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            try:
                # A timestamp older than the skew window can never be
                # accepted again, so its nonce no longer needs to live
                # forever.  TTL is deliberately much larger than 30s.
                conn.execute(
                    "DELETE FROM signed_admissions WHERE received_at < ?",
                    (now - self._ttl_seconds,),
                )
                conn.execute(
                    "INSERT INTO signed_admissions "
                    "(client_id, nonce, request_ts, received_at, method, "
                    " raw_path, signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        request.client_id,
                        request.nonce,
                        request.timestamp,
                        now,
                        request.method,
                        request.raw_path_query,
                        request.signature,
                    ),
                )
                conn.execute("COMMIT")
                return "stored"
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                return "duplicate"
            except sqlite3.Error:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                return "unavailable"
        except sqlite3.Error:
            # Schema creation failed (e.g. read-only database file, busy beyond
            # the busy timeout).  Fail closed.
            return "unavailable"
        finally:
            conn.close()


class Authenticator:
    """Verify a signed request, then reserve its nonce in the shared ledger."""

    def __init__(
        self,
        ledger: AdmissionLedger,
        clients: Mapping[str, str] | None = None,
        *,
        clock=time.time,
        max_skew_seconds: float = MAX_SKEW_SECONDS,
    ):
        self.ledger = ledger
        self.clients = dict(load_clients() if clients is None else clients)
        self._clock = clock
        self.max_skew_seconds = max_skew_seconds

    # -- public ---------------------------------------------------------
    def verify(
        self,
        headers: Mapping[str, str],
        method: str,
        raw_path_query: str,
        *,
        now: float | None = None,
    ) -> SignedRequest:
        now = self._clock() if now is None else now
        client_id = (headers.get(HEADER_CLIENT) or "").strip()
        timestamp_raw = (headers.get(HEADER_TIMESTAMP) or "").strip()
        nonce = (headers.get(HEADER_NONCE) or "").strip()
        signature = (headers.get(HEADER_SIGNATURE) or "").strip()

        if not client_id or not timestamp_raw or not nonce or not signature:
            raise AuthError("signature_required")
        if not _CLIENT_RE.match(client_id):
            raise AuthError("invalid_client_id")
        if not _NONCE_RE.match(nonce):
            raise AuthError("invalid_nonce")
        if not re.fullmatch(r"-?[0-9]{1,20}", timestamp_raw):
            raise AuthError("invalid_timestamp")
        timestamp = int(timestamp_raw)
        skew = now - timestamp
        if abs(skew) > self.max_skew_seconds:
            raise AuthError(
                "timestamp_skew",
                max_skew_seconds=self.max_skew_seconds,
                skew_seconds=round(skew, 3),
            )

        secret = self.clients.get(client_id)
        if not secret:
            # Do not reveal whether a client id exists: verify against a
            # throw-away secret so unknown clients and wrong secrets produce
            # the same result (and roughly the same timing).
            secret = secrets.token_hex(32)

        expected = sign(
            secret, client_id, timestamp, nonce, method, raw_path_query
        )
        if not hmac.compare_digest(expected, signature.lower()):
            raise AuthError("invalid_signature")

        return SignedRequest(
            client_id=client_id,
            timestamp=timestamp,
            nonce=nonce,
            method=method.upper(),
            raw_path_query=raw_path_query,
            signature=signature.lower(),
        )

    def verify_and_admit(
        self,
        headers: Mapping[str, str],
        method: str,
        raw_path_query: str,
        *,
        now: float | None = None,
    ) -> SignedRequest:
        request = self.verify(headers, method, raw_path_query, now=now)
        result = self.ledger.admit(request)
        if result == "duplicate":
            raise AuthError("replay_detected", status_code=409)
        if result != "stored":
            raise AuthError("admission_ledger_unavailable", status_code=503)
        return request
