"""Per-User static API keys. Format: inb_<8-char prefix>_<secret>.

Only sha512 hashes are stored (matches upstream token model); verification is
constant-time; lookup is prefix-indexed. Plaintext exists only in the mint
response — never persisted or logged (enforced by test).
"""

import hashlib
import hmac
import secrets

from powerdns_api_proxy.inberlin.store import Store

KEY_NAMESPACE = "inb"


def sha512(value: str) -> str:
    """Hex sha512 of a token — the one hash helper for the whole extension
    (static env lookup and TN keys share the upstream token model)."""
    return hashlib.sha512(value.encode()).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Returns (plaintext, prefix, hash)."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    plaintext = f"{KEY_NAMESPACE}_{prefix}_{secret}"
    return plaintext, prefix, sha512(plaintext)


def parse_prefix(token: str) -> str | None:
    """Extract the 8-hex-char prefix from an inb_* token, or None if malformed."""
    parts = token.split("_", 2)
    if len(parts) == 3 and parts[0] == KEY_NAMESPACE and len(parts[1]) == 8:
        return parts[1]
    return None


async def verify_key(store: Store, token: str) -> str | None:
    """Returns the canonical User for a valid, unrevoked key, else None."""
    prefix = parse_prefix(token)
    if prefix is None:
        return None
    candidate_hash = sha512(token)
    for row in await store.find_key_by_prefix(prefix):
        if hmac.compare_digest(row["key_hash"], candidate_hash):
            return row["user"]
    return None
