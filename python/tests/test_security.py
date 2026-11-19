import base64
import json
import uuid

import jwt
import pytest

from app.features.auth import security as s
from app.features.files.router import object_key

SECRET = "x" * 32


# ---------- passwords ----------


def test_password_hash_is_argon2id_with_spec_params():
    h = s.hash_password("correct horse battery")
    assert h.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert s.verify_password(h, "correct horse battery")
    assert not s.needs_rehash(h)


def test_password_verify_rejects_wrong_and_garbage():
    h = s.hash_password("correct horse battery")
    assert not s.verify_password(h, "correct horse batterY")
    assert not s.verify_password(h, " correct horse battery")  # never trimmed
    assert not s.verify_password("not-a-hash", "whatever")
    assert not s.verify_password(s.DUMMY_HASH, "whatever")


def test_hashes_are_salted():
    assert s.hash_password("same password") != s.hash_password("same password")


# ---------- opaque tokens ----------


def test_new_secret_is_32_bytes_base64url_unpadded():
    secret = s.new_secret()
    assert len(secret) == 43 and "=" not in secret
    assert len(base64.urlsafe_b64decode(secret + "=")) == 32
    assert len({s.new_secret() for _ in range(100)}) == 100


def test_sha256_hex_and_constant_time_compare():
    assert s.sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert s.hashes_equal(s.sha256_hex("a"), s.sha256_hex("a"))
    assert not s.hashes_equal(s.sha256_hex("a"), s.sha256_hex("b"))


def test_refresh_token_roundtrip():
    sid, secret = uuid.uuid4(), s.new_secret()
    assert s.parse_refresh_token(s.make_refresh_token(sid, secret)) == (sid, secret)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "nope",
        "a.b",
        f"not-a-uuid.{'A' * 43}",
        f"{uuid.uuid4()}.{'A' * 42}",  # too short
        f"{uuid.uuid4()}.{'A' * 44}",  # too long
        f"{uuid.uuid4()}.{'A' * 42}=",  # padding / bad alphabet
        f"{uuid.uuid4()}.{'A' * 43}.extra",
        f"{{{uuid.uuid4()}}}.{'A' * 43}",  # braces uuid.UUID would accept
        f"{uuid.uuid4().hex}.{'A' * 43}",  # dashless
        f"{str(uuid.uuid4()).upper()}.{'A' * 43}",  # not canonical (uppercase)
        f"{uuid.uuid4()}.{'A' * 43}\n",  # trailing newline: `$` would accept it, fullmatch does not
        f"{uuid.uuid4()}\n.{'A' * 43}",
    ],
)
def test_refresh_token_parse_rejects_malformed(token):
    assert s.parse_refresh_token(token) is None


# ---------- access tokens ----------


def test_access_token_roundtrip_and_claims():
    uid, sid = uuid.uuid4(), uuid.uuid4()
    token = s.encode_access_token(SECRET, uid, sid, 900, now=1_000)
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})
    assert claims == {"sub": str(uid), "sid": str(sid), "iat": 1_000, "exp": 1_900}
    fresh = s.encode_access_token(SECRET, uid, sid, 900)
    assert s.decode_access_token(SECRET, fresh) == s.AccessClaims(uid, sid)


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_access_token_rejects_expired_wrong_key_none_and_other_algs():
    uid, sid = uuid.uuid4(), uuid.uuid4()
    assert s.decode_access_token(SECRET, s.encode_access_token(SECRET, uid, sid, 900, now=1_000)) is None  # expired
    assert s.decode_access_token("y" * 32, s.encode_access_token(SECRET, uid, sid, 900)) is None
    payload = {"sub": str(uid), "sid": str(sid), "iat": 2**31, "exp": 2**31 + 900}
    assert s.decode_access_token(SECRET, f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(payload)}.") is None
    hs512 = jwt.encode(payload, SECRET + SECRET, algorithm="HS512")
    assert s.decode_access_token(SECRET + SECRET, hs512) is None
    assert s.decode_access_token(SECRET, "garbage") is None


def test_access_token_requires_exp_and_uuid_claims():
    no_exp = jwt.encode({"sub": str(uuid.uuid4()), "sid": str(uuid.uuid4()), "iat": 1}, SECRET, algorithm="HS256")
    assert s.decode_access_token(SECRET, no_exp) is None
    bad_sub = jwt.encode({"sub": "admin", "sid": str(uuid.uuid4()), "iat": 1, "exp": 2**31}, SECRET, algorithm="HS256")
    assert s.decode_access_token(SECRET, bad_sub) is None


# ---------- object keys ----------


def test_object_key_never_contains_the_client_filename():
    uid, fid = uuid.uuid4(), uuid.uuid4()
    assert object_key(uid, fid, "../../Evil Name.PNG") == f"users/{uid}/{fid}.png"
    assert object_key(uid, fid, "noext") == f"users/{uid}/{fid}"
    assert object_key(uid, fid, "x.tar.gz") == f"users/{uid}/{fid}.gz"
    assert object_key(uid, fid, "x.verylongextension") == f"users/{uid}/{fid}"
    assert object_key(uid, fid, "x.p n g") == f"users/{uid}/{fid}"


def test_iat_is_not_validated():
    uid, sid = uuid.uuid4(), uuid.uuid4()
    future_iat = jwt.encode({"sub": str(uid), "sid": str(sid), "iat": 2**31, "exp": 2**31 + 900}, SECRET, "HS256")
    no_iat = jwt.encode({"sub": str(uid), "sid": str(sid), "exp": 2**31}, SECRET, algorithm="HS256")
    assert s.decode_access_token(SECRET, future_iat) == s.AccessClaims(uid, sid)  # replica clock skew is fine
    assert s.decode_access_token(SECRET, no_iat) == s.AccessClaims(uid, sid)


# ---------- reuse detection ----------


def test_reuse_only_when_the_presented_hash_is_the_rotated_out_one():
    previous = s.sha256_hex("old-secret")
    assert s.is_reuse(previous, s.sha256_hex("old-secret"))
    assert not s.is_reuse(previous, s.sha256_hex("a guess"))  # a never-issued secret revokes nothing
    assert not s.is_reuse(None, s.sha256_hex("a guess"))  # never rotated: nothing can be a replay
