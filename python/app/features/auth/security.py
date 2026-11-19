"""Pure, security-relevant helpers: passwords, opaque tokens, JWTs. No I/O, unit tested in tests/."""

import base64
import hashlib
import hmac
import re
import secrets
import time
import uuid
from dataclasses import dataclass

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# ---------- passwords: argon2id, m=19456 KiB, t=2, p=1, PHC string ----------

_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# Verified against when the email is unknown, so a miss costs the same argon2 work as a wrong password.
DUMMY_HASH = hash_password(secrets.token_urlsafe(32))

# ---------- opaque tokens ----------

_SECRET = re.compile(r"[A-Za-z0-9_-]{43}")  # 32 bytes, base64url, no padding; fullmatch only (`$` takes a \n)


def new_secret() -> str:
    """32 CSPRNG bytes, base64url without padding (43 chars)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hashes_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def is_reuse(previous_hash: str | None, presented_hash: str) -> bool:
    """Reuse detection: only the secret this session's current one replaced proves a replay. Any other
    well-formed guess is just wrong; the session id is public, so it must not be enough to revoke."""
    return previous_hash is not None and hashes_equal(previous_hash, presented_hash)


def make_refresh_token(session_id: uuid.UUID, secret: str) -> str:
    return f"{session_id}.{secret}"


def parse_refresh_token(token: str) -> tuple[uuid.UUID, str] | None:
    """`<session_id>.<secret>` -> (session_id, secret), or None when malformed."""
    parts = token.split(".")
    if len(parts) != 2 or not _SECRET.fullmatch(parts[1]):
        return None
    try:
        session_id = uuid.UUID(parts[0])
    except ValueError:
        return None
    if str(session_id) != parts[0]:  # canonical 36-char lowercase only; uuid.UUID tolerates braces/urn/no dashes
        return None
    return session_id, parts[1]


# ---------- access tokens: JWT HS256 ----------


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID


def encode_access_token(
    secret: str, user_id: uuid.UUID, session_id: uuid.UUID, ttl: int, now: int | None = None
) -> str:
    iat = int(time.time()) if now is None else now
    claims = {"sub": str(user_id), "sid": str(session_id), "iat": iat, "exp": iat + ttl}
    return jwt.encode(claims, secret, algorithm="HS256")


def decode_access_token(secret: str, token: str) -> AccessClaims | None:
    """Pinned to HS256 (`none` and every other alg are rejected), `exp` required and checked. `secret` is used
    byte for byte."""
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            # `iat` is informational: not validated, so clock skew between replicas never causes a 401.
            options={
                "require": ["exp", "sub", "sid"],
                "verify_exp": True,
                "verify_signature": True,
                "verify_iat": False,
            },
        )
        return AccessClaims(uuid.UUID(claims["sub"]), uuid.UUID(claims["sid"]))
    except (jwt.InvalidTokenError, ValueError, TypeError, AttributeError):
        return None
