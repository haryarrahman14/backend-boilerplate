"""Pure decisions: who may change whom, and what a verified login is still refused with."""

import uuid
from datetime import UTC, datetime

from app.features.auth.service import login_refusal
from app.features.users.models import User
from app.features.users.service import self_change_refusal

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def user(**kw) -> User:
    return User(id=kw.pop("id", uuid.uuid4()), role=kw.pop("role", "user"), **kw)


# ---------- self-modification ----------


def test_admin_cannot_demote_or_disable_themselves():
    me = user(role="admin")
    assert self_change_refusal(me.id, me, "user", None).code == "forbidden"
    assert self_change_refusal(me.id, me, None, True).code == "forbidden"
    assert self_change_refusal(me.id, me, "user", False).code == "forbidden"


def test_no_op_on_oneself_is_allowed():
    me = user(role="admin")
    assert self_change_refusal(me.id, me, None, None) is None
    assert self_change_refusal(me.id, me, "admin", None) is None  # not a change
    assert self_change_refusal(me.id, me, None, False) is None  # already enabled


def test_admin_may_change_anyone_else():
    other = user(role="admin")
    actor = uuid.uuid4()
    assert self_change_refusal(actor, other, "user", True) is None


# ---------- login after the password verified ----------


def test_active_verified_user_is_let_in():
    assert login_refusal(user(email_verified_at=NOW), require_verified_email=True) is None
    assert login_refusal(user(), require_verified_email=False) is None


def test_disabled_account_is_refused_with_account_disabled():
    refusal = login_refusal(user(disabled_at=NOW, email_verified_at=NOW), require_verified_email=False)
    assert (refusal.status, refusal.code) == (403, "account_disabled")


def test_disabled_wins_over_unverified():
    refusal = login_refusal(user(disabled_at=NOW), require_verified_email=True)
    assert refusal.code == "account_disabled"


def test_unverified_when_required():
    refusal = login_refusal(user(), require_verified_email=True)
    assert (refusal.status, refusal.code) == (403, "email_not_verified")
