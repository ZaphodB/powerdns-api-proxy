import asyncio
import sqlite3

import pytest

from powerdns_api_proxy.inberlin.keys import generate_key, parse_prefix, verify_key
from powerdns_api_proxy.inberlin.mapping import MappingState
from powerdns_api_proxy.inberlin.store import GenerationMismatch, Store


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "s.sqlite"))
    yield s
    s.close()


def test_mapping_cas(store, tmp_path):
    state = MappingState(store, [])
    run(state.load())
    assert state.view.generation == 0
    gen = run(state.replace(0, {"alice": ["a.example"]}, "t"))
    assert gen == 1
    with pytest.raises(GenerationMismatch):
        run(state.replace(0, {"bob": ["b.example"]}, "t"))
    gen = run(state.patch(1, {"bob": ["b.example"]}, {}, "t"))
    assert gen == 2
    assert state.view.owner_of("b.example.") == "bob"
    gen = run(state.patch(2, {}, {"alice": ["a.example"]}, "t"))
    assert state.view.owner_of("a.example.") is None


def test_mapping_survives_restart(tmp_path):
    path = str(tmp_path / "s.sqlite")
    s1 = Store(path)
    state1 = MappingState(s1, [])
    run(state1.load())
    run(state1.replace(0, {"alice": ["kunde.example"]}, "t"))
    s1.close()

    s2 = Store(path)
    state2 = MappingState(s2, [])
    run(state2.load())
    assert state2.view.generation == 1
    assert state2.view.owner_of("www.kunde.example.") == "alice"
    s2.close()


def test_key_lifecycle(store):
    plaintext, prefix, key_hash = generate_key()
    assert parse_prefix(plaintext) == prefix
    run(store.insert_key("alice", prefix, key_hash, "lab", "webui-act-as", 10))
    assert run(verify_key(store, plaintext)) == "alice"
    assert run(verify_key(store, plaintext + "x")) is None
    assert run(verify_key(store, "not-a-key")) is None

    keys = run(store.list_keys("alice"))
    assert len(keys) == 1 and keys[0]["revoked_at"] is None
    # plaintext never stored
    assert plaintext not in str(keys)
    assert run(store.revoke_key(keys[0]["id"], "alice"))
    assert run(verify_key(store, plaintext)) is None


def test_key_revoke_scoping(store):
    plaintext, prefix, key_hash = generate_key()
    kid = run(store.insert_key("alice", prefix, key_hash, None, "oidc", 10))
    keys = run(store.list_keys("alice"))
    kid = keys[0]["id"]
    assert not run(store.revoke_key(kid, "bob"))  # not bob's key
    assert run(store.revoke_key(kid, None))  # admin


def test_key_cap_enforced_in_transaction(store):
    import pytest
    from powerdns_api_proxy.inberlin.store import KeyLimitReached

    for _ in range(2):
        plaintext, prefix, key_hash = generate_key()
        run(store.insert_key("alice", prefix, key_hash, None, "oidc", 2))
    plaintext, prefix, key_hash = generate_key()
    with pytest.raises(KeyLimitReached):
        run(store.insert_key("alice", prefix, key_hash, None, "oidc", 2))
    # revoking frees a slot
    keys = run(store.list_keys("alice"))
    assert run(store.revoke_key(keys[0]["id"], "alice"))
    run(store.insert_key("alice", prefix, key_hash, None, "oidc", 2))


def test_journal_state_machine(store):
    jid = run(
        store.journal_intent(
            teilnehmer="alice", actor="webui", actor_kind="webui-act-as",
            impersonator=None, webui_user="alice", zone="kunde.example.",
            method="PATCH", path="/api/v1/servers/localhost/zones/kunde.example.",
            operation="rrset-patch", raw_request="{}", before_state=None,
        )
    )
    entry = run(store.journal_get(jid))
    assert entry["status"] == "pending"
    run(
        store.journal_finalize(
            jid, status="committed", status_code=204, after_state=None,
            rollbackable=True,
            rrsets=[("www.kunde.example.", "A", None, '{"ttl": 300}')],
        )
    )
    entry = run(store.journal_get(jid))
    assert entry["status"] == "committed"
    assert entry["rollbackable"] == 1
    assert entry["rrsets"][0]["rtype"] == "A"

    rows = run(store.journal_query(teilnehmer="alice"))
    assert len(rows) == 1
    rows = run(store.journal_query(name="www.kunde.example.", rtype="A"))
    assert len(rows) == 1
    rows = run(store.journal_query(name="other.example.", rtype="A"))
    assert rows == []


def test_journal_resolve_uncertain(store):
    jid = run(
        store.journal_intent(
            teilnehmer=None, actor="x", actor_kind="static", impersonator=None,
            webui_user=None, zone=".", method="POST", path="/p", operation="other",
            raw_request=None, before_state=None,
        )
    )
    run(
        store.journal_finalize(
            jid, status="uncertain", status_code=204, after_state=None, rollbackable=False
        )
    )
    assert run(store.journal_resolve(jid, "committed", "admin:x"))
    assert not run(store.journal_resolve(jid, "failed", "admin:x"))  # already resolved


def _intent(store, status=None):
    jid = run(
        store.journal_intent(
            teilnehmer=None, actor="x", actor_kind="static", impersonator=None,
            webui_user=None, zone=".", method="POST", path="/p", operation="other",
            raw_request=None, before_state=None,
        )
    )
    if status:
        run(
            store.journal_finalize(
                jid, status=status, status_code=200, after_state=None,
                rollbackable=False,
            )
        )
    return jid


def test_journal_prune_keeps_pending_and_uncertain(store):
    ids = {s: _intent(store, s) for s in ("committed", "failed", "uncertain")}
    ids["pending"] = _intent(store)
    # retention 0 days = everything is past the cutoff
    run(store.journal_prune(0))
    assert run(store.journal_get(ids["committed"])) is None
    assert run(store.journal_get(ids["failed"])) is None
    # unreconciled rows must never age out silently
    assert run(store.journal_get(ids["uncertain"])) is not None
    assert run(store.journal_get(ids["pending"])) is not None


def test_journal_prune_survives_rollback_fk(store):
    # a rollback entry referencing a pruned parent must not break the prune
    parent = _intent(store, "committed")
    child = run(
        store.journal_intent(
            teilnehmer=None, actor="x", actor_kind="static", impersonator=None,
            webui_user=None, zone=".", method="POST", path="/p", operation="other",
            raw_request=None, before_state=None, rollback_of=parent,
        )
    )
    run(
        store.journal_finalize(
            child, status="committed", status_code=200, after_state=None,
            rollbackable=False,
        )
    )
    # age only the parent past the cutoff
    aged = sqlite3.connect(store.path)
    aged.execute("UPDATE journal SET ts = '2000-01-01T00:00:00+00:00' WHERE id = ?", (parent,))
    aged.commit()
    aged.close()
    assert run(store.journal_prune(365)) == 1  # parent pruned, no IntegrityError
    surviving = run(store.journal_get(child))
    assert surviving is not None
    assert surviving["rollback_of"] is None  # detached, not dangling


def test_journal_query_limit_clamped(store):
    for _ in range(3):
        _intent(store, "committed")
    # SQLite treats LIMIT -1 as unlimited — the store must clamp
    assert len(run(store.journal_query(limit=-1))) == 1
    assert len(run(store.journal_query(limit=2))) == 2


def test_mapping_and_override_updates_serialized(store):
    """Round-7 regression: concurrent mapping replace and override add must
    both land in the final view — before the mutation lock, the interleaved
    store-read -> view-swap sequences could publish a view built from stale
    data, silently dropping one of the updates."""
    state = MappingState(store, [])
    run(state.load())
    run(state.replace(0, {"alice": ["a.example"]}, "t"))

    async def scenario():
        await asyncio.gather(
            state.add_override("ov.example.", "bob", "t", None),
            state.replace(1, {"carol": ["c.example"]}, "t"),
        )

    run(scenario())
    # final view reflects BOTH the newest mapping and the override
    assert state.view.owner_of("c.example.") == "carol"
    assert state.view.owner_of("a.example.") is None
    assert state.view.owner_of("ov.example.") == "bob"
    # and matches what the store has on disk
    gen, mapping, overrides = run(store.load_mapping())
    assert gen == state.view.generation == 2
    assert overrides == {"ov.example.": "bob"}
