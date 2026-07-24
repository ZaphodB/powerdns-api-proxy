"""SQLite state store: mapping snapshot, override grants, TN api keys, journal.

Single-writer discipline: all writes go through Store._write() which holds an
asyncio.Lock and runs the sync sqlite3 work in a thread (never blocking the
event loop) on the dedicated write connection. Reads use per-thread
connections — WAL mode lets them run concurrently with each other and with
the writer. busy_timeout 5000. One uvicorn worker is an operational
requirement (docs/authz-flow.md).
"""

import asyncio
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from powerdns_api_proxy.logging import logger

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mapping_snapshot (
  generation INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mapping_entry (
  user TEXT NOT NULL,
  zone TEXT NOT NULL,
  PRIMARY KEY (user, zone)
);
CREATE TABLE IF NOT EXISTS override_grant (
  id INTEGER PRIMARY KEY,
  zone TEXT NOT NULL UNIQUE,
  user TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  note TEXT
);
CREATE TABLE IF NOT EXISTS user_identity (
  user TEXT PRIMARY KEY,
  oidc_sub TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS api_key (
  id INTEGER PRIMARY KEY,
  user TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at TEXT NOT NULL,
  created_via TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS api_key_prefix ON api_key(key_prefix);
CREATE TABLE IF NOT EXISTS journal (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|committed|failed|uncertain
  user TEXT,
  actor TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  impersonator TEXT,
  webui_user TEXT,
  zone TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  operation TEXT NOT NULL,       -- rrset-patch|zone-create|zone-delete|zone-meta|crypto|tsig|other
  raw_request TEXT,
  before_state TEXT,
  after_state TEXT,
  status_code INTEGER,
  rollbackable INTEGER NOT NULL DEFAULT 0,
  rollback_of INTEGER REFERENCES journal(id),
  resolved_by TEXT
);
CREATE INDEX IF NOT EXISTS journal_zone_ts ON journal(zone, ts);
CREATE INDEX IF NOT EXISTS journal_tn_ts ON journal(user, ts);
CREATE INDEX IF NOT EXISTS journal_status ON journal(status);
CREATE INDEX IF NOT EXISTS journal_rollback_of ON journal(rollback_of);
CREATE TABLE IF NOT EXISTS journal_rrset (
  id INTEGER PRIMARY KEY,
  journal_id INTEGER NOT NULL REFERENCES journal(id),
  name TEXT NOT NULL,
  rtype TEXT NOT NULL,
  before_rrset TEXT,
  after_rrset TEXT
);
CREATE INDEX IF NOT EXISTS journal_rrset_journal ON journal_rrset(journal_id);
CREATE INDEX IF NOT EXISTS journal_rrset_name ON journal_rrset(name, rtype);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bump_generation(
    c: sqlite3.Connection, expected_generation: int, actor: str, payload: dict
) -> tuple[int, str]:
    """CAS-check expected vs current generation and commit the next snapshot
    row. Shared by mapping and override writes: both race the exporter's
    full-replace, so both CAS and bump the same sequence (docs/api-contract.md
    lines 36-42). Caller holds the write transaction."""
    row = c.execute(
        "SELECT generation FROM mapping_snapshot ORDER BY generation DESC LIMIT 1"
    ).fetchone()
    current = row["generation"] if row else 0
    if current != expected_generation:
        raise GenerationMismatch(current)
    new_gen = current + 1
    applied_at = _utcnow()
    c.execute(
        "INSERT INTO mapping_snapshot (generation, applied_at, actor, payload)"
        " VALUES (?, ?, ?, ?)",
        (new_gen, applied_at, actor, json.dumps(payload)),
    )
    return new_gen, applied_at


class Store:
    def __init__(self, path: str):
        self.path = path
        self._write_lock = asyncio.Lock()
        # check_same_thread=False lets asyncio.to_thread run DB work off the
        # event loop, but a single sqlite3.Connection is NOT safe for concurrent
        # use across threads. This lock serializes access to the WRITE
        # connection; reads get per-thread connections (WAL readers don't
        # block the writer or each other).
        self._conn_lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._local = threading.local()
        # executor threads outlive the Store (and tests create many Stores) —
        # track read connections so close() can release them deterministically
        self._read_conns: list[sqlite3.Connection] = []

    def _read_conn(self) -> sqlite3.Connection:
        """Per-thread read connection (asyncio.to_thread pool threads)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
            self._read_conns.append(conn)
        return conn

    def close(self) -> None:
        for conn in self._read_conns:
            try:
                conn.close()
            except Exception:
                pass
        self._read_conns.clear()
        self._conn.close()

    async def _write(self, fn: Callable[[sqlite3.Connection], Any]) -> Any:
        """Serialized write inside BEGIN IMMEDIATE, off the event loop."""
        async with self._write_lock:

            def run():
                with self._conn_lock:
                    try:
                        self._conn.execute("BEGIN IMMEDIATE")
                        result = fn(self._conn)
                        self._conn.commit()
                        return result
                    except Exception:
                        self._conn.rollback()
                        raise

            return await asyncio.to_thread(run)

    async def _read(self, fn: Callable[[sqlite3.Connection], Any]) -> Any:
        """Read off the event loop on a per-thread connection — concurrent
        with writes and other reads (WAL snapshot isolation)."""
        return await asyncio.to_thread(lambda: fn(self._read_conn()))

    async def writable(self) -> bool:
        """Health probe for /proxy/v1/ready: can we open a write transaction?"""
        try:
            await self._write(lambda c: c.execute("SELECT 1").fetchone())
            return True
        except Exception:
            logger.exception("journal store not writable")
            return False

    # -- mapping ----------------------------------------------------------

    async def load_mapping(
        self,
    ) -> tuple[int, str, dict[str, set[str]], dict[str, str]]:
        """Returns (generation, applied_at, {tn: {zones}}, {override_zone: tn}).

        applied_at is the commit timestamp of the latest generation ("" for an
        empty store)."""

        def run(c: sqlite3.Connection):
            row = c.execute(
                "SELECT generation, applied_at FROM mapping_snapshot"
                " ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            generation = row["generation"] if row else 0
            applied_at = row["applied_at"] if row else ""
            mapping: dict[str, set[str]] = {}
            for r in c.execute("SELECT user, zone FROM mapping_entry"):
                mapping.setdefault(r["user"], set()).add(r["zone"])
            overrides = {
                r["zone"]: r["user"]
                for r in c.execute("SELECT zone, user FROM override_grant")
            }
            return generation, applied_at, mapping, overrides

        return await self._read(run)

    async def save_mapping(
        self,
        expected_generation: int,
        mapping: dict[str, set[str]],
        actor: str,
        payload: dict,
    ) -> tuple[int, str]:
        """CAS write of the full normalized mapping.

        Returns (new generation, applied_at)."""

        def run(c: sqlite3.Connection) -> tuple[int, str]:
            new_gen, applied_at = _bump_generation(
                c, expected_generation, actor, payload
            )
            c.execute("DELETE FROM mapping_entry")
            c.executemany(
                "INSERT INTO mapping_entry (user, zone) VALUES (?, ?)",
                [(tn, z) for tn, zones in mapping.items() for z in zones],
            )
            return new_gen, applied_at

        return await self._write(run)

    # -- overrides --------------------------------------------------------

    async def list_overrides(self) -> list[dict]:
        return await self._read(
            lambda c: [
                dict(r) for r in c.execute("SELECT * FROM override_grant ORDER BY id")
            ]
        )

    async def add_override(
        self,
        zone: str,
        user: str,
        created_by: str,
        note: str | None,
        expected_generation: int,
    ) -> tuple[int, int]:
        """Insert an override grant and bump the shared mapping generation in
        the same transaction. Returns (override_id, new generation)."""

        def run(c: sqlite3.Connection) -> tuple[int, int]:
            new_gen, _ = _bump_generation(
                c,
                expected_generation,
                created_by,
                {"override_add": {"zone": zone, "user": user, "note": note}},
            )
            cur = c.execute(
                "INSERT INTO override_grant (zone, user, created_by, created_at, note)"
                " VALUES (?, ?, ?, ?, ?)",
                (zone, user, created_by, _utcnow(), note),
            )
            return int(cur.lastrowid or 0), new_gen

        return await self._write(run)

    async def delete_override(
        self, override_id: int, expected_generation: int, actor: str
    ) -> tuple[bool, int]:
        """Delete an override grant, bumping the generation only when a row was
        actually removed. Returns (deleted, new-or-current generation).
        A stale generation raises GenerationMismatch even for a missing id —
        the caller's view of the mapping is out of date either way."""

        def run(c: sqlite3.Connection) -> tuple[bool, int]:
            row = c.execute(
                "SELECT generation FROM mapping_snapshot"
                " ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            current = row["generation"] if row else 0
            if current != expected_generation:
                raise GenerationMismatch(current)
            cur = c.execute("DELETE FROM override_grant WHERE id = ?", (override_id,))
            if cur.rowcount == 0:
                return False, current
            new_gen, _ = _bump_generation(
                c,
                expected_generation,
                actor,
                {"override_delete": {"id": override_id}},
            )
            return True, new_gen

        return await self._write(run)

    # -- user identity bridge --------------------------------------

    async def user_for_sub(self, oidc_sub: str) -> Optional[str]:
        return await self._read(
            lambda c: (lambda row: row["user"] if row else None)(
                c.execute(
                    "SELECT user FROM user_identity WHERE oidc_sub = ?",
                    (oidc_sub,),
                ).fetchone()
            )
        )

    async def bind_user_sub(self, user: str, oidc_sub: str) -> None:
        await self._write(
            lambda c: c.execute(
                "INSERT OR REPLACE INTO user_identity (user, oidc_sub) VALUES (?, ?)",
                (user, oidc_sub),
            )
        )

    # -- api keys ---------------------------------------------------------

    async def insert_key(
        self,
        user: str,
        prefix: str,
        key_hash: str,
        label: str | None,
        via: str,
        max_keys: int,
    ) -> int:
        """Inserts a key, enforcing the per-TN cap inside the same transaction
        (a router-side pre-check alone would be a TOCTOU across two awaits)."""

        def run(c: sqlite3.Connection) -> int:
            count = c.execute(
                "SELECT COUNT(*) AS n FROM api_key WHERE user = ? AND revoked_at IS NULL",
                (user,),
            ).fetchone()["n"]
            if count >= max_keys:
                raise KeyLimitReached(count)
            cur = c.execute(
                "INSERT INTO api_key (user, key_prefix, key_hash, label, created_at, created_via)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (user, prefix, key_hash, label, _utcnow(), via),
            )
            return int(cur.lastrowid or 0)

        return await self._write(run)

    async def count_active_keys(self, user: str) -> int:
        return await self._read(
            lambda c: c.execute(
                "SELECT COUNT(*) AS n FROM api_key WHERE user = ? AND revoked_at IS NULL",
                (user,),
            ).fetchone()["n"]
        )

    async def find_key_by_prefix(self, prefix: str) -> list[dict]:
        return await self._read(
            lambda c: [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM api_key WHERE key_prefix = ? AND revoked_at IS NULL",
                    (prefix,),
                )
            ]
        )

    async def list_keys(self, user: str) -> list[dict]:
        """Contract shape (docs/api-contract.md): id, prefix, label, ... —
        the DB column is key_prefix, the wire name is prefix."""
        return await self._read(
            lambda c: [
                {
                    ("prefix" if k == "key_prefix" else k): r[k]
                    for k in (
                        "id",
                        "key_prefix",
                        "label",
                        "created_at",
                        "created_via",
                        "revoked_at",
                    )
                }
                for r in c.execute(
                    "SELECT * FROM api_key WHERE user = ? ORDER BY id", (user,)
                )
            ]
        )

    async def revoke_key(self, key_id: int, user: str | None) -> bool:
        """user None = admin (any key)."""

        def run(c: sqlite3.Connection) -> bool:
            if user is None:
                cur = c.execute(
                    "UPDATE api_key SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                    (_utcnow(), key_id),
                )
            else:
                cur = c.execute(
                    "UPDATE api_key SET revoked_at = ? WHERE id = ? AND user = ?"
                    " AND revoked_at IS NULL",
                    (_utcnow(), key_id, user),
                )
            return cur.rowcount > 0

        return await self._write(run)

    # -- journal ----------------------------------------------------------

    async def journal_intent(
        self,
        *,
        user: Optional[str],
        actor: str,
        actor_kind: str,
        impersonator: Optional[str],
        webui_user: Optional[str],
        zone: str,
        method: str,
        path: str,
        operation: str,
        raw_request: Optional[str],
        before_state: Optional[str],
        rollback_of: Optional[int] = None,
    ) -> int:
        def run(c: sqlite3.Connection) -> int:
            cur = c.execute(
                "INSERT INTO journal (ts, status, user, actor, actor_kind,"
                " impersonator, webui_user, zone, method, path, operation,"
                " raw_request, before_state, rollback_of)"
                " VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _utcnow(),
                    user,
                    actor,
                    actor_kind,
                    impersonator,
                    webui_user,
                    zone,
                    method,
                    path,
                    operation,
                    raw_request,
                    before_state,
                    rollback_of,
                ),
            )
            return int(cur.lastrowid or 0)

        return await self._write(run)

    async def journal_finalize(
        self,
        journal_id: int,
        *,
        status: str,
        status_code: Optional[int],
        after_state: Optional[str],
        rollbackable: bool,
        rrsets: Optional[list[tuple[str, str, Optional[str], Optional[str]]]] = None,
    ) -> None:
        rrsets = rrsets or []

        def run(c: sqlite3.Connection) -> None:
            # Idempotent: only a pending/uncertain row transitions, and only
            # then do we insert rrset rows — a retried finalize is a no-op
            # instead of duplicating inverse data.
            cur = c.execute(
                "UPDATE journal SET status = ?, status_code = ?, after_state = ?,"
                " rollbackable = ? WHERE id = ? AND status IN ('pending', 'uncertain')",
                (status, status_code, after_state, int(rollbackable), journal_id),
            )
            if cur.rowcount == 0:
                return
            c.executemany(
                "INSERT INTO journal_rrset (journal_id, name, rtype, before_rrset, after_rrset)"
                " VALUES (?, ?, ?, ?, ?)",
                [(journal_id, n, t, b, a) for n, t, b, a in rrsets],
            )

        await self._write(run)

    async def journal_get(self, journal_id: int) -> Optional[dict]:
        def run(c: sqlite3.Connection):
            row = c.execute(
                "SELECT * FROM journal WHERE id = ?", (journal_id,)
            ).fetchone()
            if not row:
                return None
            entry = dict(row)
            entry["rrsets"] = [
                dict(r)
                for r in c.execute(
                    "SELECT name, rtype, before_rrset, after_rrset FROM journal_rrset"
                    " WHERE journal_id = ?",
                    (journal_id,),
                )
            ]
            return entry

        return await self._read(run)

    async def journal_query(
        self,
        *,
        user: Optional[str] = None,
        zone: Optional[str] = None,
        name: Optional[str] = None,
        rtype: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Filtered journal listing (newest first, limit capped at 1000).
        name/rtype filters join through journal_rrset."""

        def run(c: sqlite3.Connection):
            sql = "SELECT DISTINCT j.* FROM journal j"
            where: list[str] = []
            params: list[Any] = []
            if name or rtype:
                sql += " JOIN journal_rrset r ON r.journal_id = j.id"
                if name:
                    where.append("r.name = ?")
                    params.append(name)
                if rtype:
                    where.append("r.rtype = ?")
                    params.append(rtype)
            if user:
                where.append("j.user = ?")
                params.append(user)
            if zone:
                where.append("j.zone = ?")
                params.append(zone)
            if since:
                where.append("j.ts >= ?")
                params.append(since)
            if until:
                where.append("j.ts <= ?")
                params.append(until)
            if status:
                where.append("j.status = ?")
                params.append(status)
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY j.id DESC LIMIT ? OFFSET ?"
            # clamp both ends: SQLite treats LIMIT -1 as unlimited
            params += [max(1, min(limit, 1000)), max(0, offset)]
            return [dict(r) for r in c.execute(sql, params)]

        return await self._read(run)

    async def journal_resolve(
        self, journal_id: int, status: str, resolved_by: str
    ) -> bool:
        """Admin finalization of a pending/uncertain row; False if already settled."""

        def run(c: sqlite3.Connection) -> bool:
            cur = c.execute(
                "UPDATE journal SET status = ?, resolved_by = ? WHERE id = ?"
                " AND status IN ('pending', 'uncertain')",
                (status, resolved_by, journal_id),
            )
            return cur.rowcount > 0

        return await self._write(run)

    async def journal_prune(self, retention_days: int) -> int:
        """Delete settled entries older than the retention window; pending AND
        uncertain rows are kept regardless of age — both still need admin
        reconciliation and must never age out silently."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=retention_days)
        ).isoformat()

        def run(c: sqlite3.Connection) -> int:
            c.execute(
                "DELETE FROM journal_rrset WHERE journal_id IN"
                " (SELECT id FROM journal WHERE ts < ? AND status IN ('committed', 'failed'))",
                (cutoff,),
            )
            # rollback_of has no ON DELETE action and foreign_keys is ON:
            # detach surviving children first, or deleting a referenced parent
            # raises IntegrityError and kills every future prune run.
            c.execute(
                "UPDATE journal SET rollback_of = NULL WHERE rollback_of IN"
                " (SELECT id FROM journal WHERE ts < ? AND status IN ('committed', 'failed'))",
                (cutoff,),
            )
            cur = c.execute(
                "DELETE FROM journal WHERE ts < ? AND status IN ('committed', 'failed')",
                (cutoff,),
            )
            return cur.rowcount

        return await self._write(run)

    async def db_size_bytes(self) -> int:
        def run(c: sqlite3.Connection) -> int:
            page_count = c.execute("PRAGMA page_count").fetchone()[0]
            page_size = c.execute("PRAGMA page_size").fetchone()[0]
            return page_count * page_size

        return await self._read(run)


class KeyLimitReached(Exception):
    """Per-User active key cap hit (raised inside the insert txn → 409)."""

    def __init__(self, count: int):
        self.count = count
        super().__init__(f"active key limit reached ({count})")


class GenerationMismatch(Exception):
    """Mapping CAS failed: caller's If-Match generation is stale (→ 409)."""

    def __init__(self, current: int):
        self.current = current
        super().__init__(f"mapping generation mismatch, current is {current}")
