//! Account deletion and admin user management (SPEC section 5).

use uuid::Uuid;

use super::repo::{self, User};
use crate::{
    features::{auth::repo as auth_repo, files::repo as files_repo},
    platform::{
        AppState,
        error::{AppError, AppResult},
    },
};

const KEYS_PAGE: i64 = 500;

/// An admin may not lock themselves out: no own role change, no self-disable. Re-sending the
/// current role or `disabled: false` on oneself is a no-op and allowed.
pub fn is_forbidden_self_change(
    actor: Uuid,
    target: &User,
    role: Option<&str>,
    disabled: Option<bool>,
) -> bool {
    actor == target.id && (role.is_some_and(|r| r != target.role) || disabled == Some(true))
}

/// Applies `role` / `disabled`. Disabling also revokes every session, in the same transaction
/// (lock order users -> sessions). Returns the user as stored afterwards.
pub async fn admin_update(
    state: &AppState,
    target: User,
    role: Option<&str>,
    disabled: Option<bool>,
) -> AppResult<User> {
    if role.is_none() && disabled.is_none() {
        return Ok(target);
    }
    let mut tx = state.db.begin().await?;
    if let Some(role) = role {
        repo::set_role(&mut *tx, target.id, role).await?;
    }
    if let Some(disabled) = disabled {
        repo::set_disabled(&mut *tx, target.id, disabled).await?;
        if disabled {
            auth_repo::revoke_user_sessions(&mut *tx, target.id, None).await?;
        }
    }
    let user = repo::find_by_id(&mut *tx, target.id)
        .await?
        .ok_or(AppError::NotFound)?;
    tx.commit().await?;
    Ok(user)
}

/// Deletes an account, in the SPEC's order: revoke every session (committed on its own, so access
/// stops even if a later step fails), delete the bucket objects, then the users row (cascade).
/// A bucket failure stops with 500 and leaves the row, so the call can simply be repeated.
/// Ceiling: an upload URL issued before this call can still create an orphan object for up to
/// 15 minutes; a bucket lifecycle rule on `users/` cleans it up.
pub async fn delete_account(state: &AppState, user_id: Uuid) -> AppResult<()> {
    auth_repo::revoke_user_sessions(&state.db, user_id, None).await?;
    let mut after = None;
    loop {
        let page = files_repo::keys_after(&state.db, user_id, after, KEYS_PAGE).await?;
        for (_, key) in &page {
            state.storage.delete(key).await?;
        }
        match page.last() {
            Some((id, _)) if page.len() as i64 == KEYS_PAGE => after = Some(*id),
            _ => break,
        }
    }
    repo::delete(&state.db, user_id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn user(id: Uuid, role: &str) -> User {
        User {
            id,
            email: "a@example.com".into(),
            password_hash: String::new(),
            name: "A".into(),
            role: role.into(),
            email_verified_at: None,
            disabled_at: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn admins_cannot_lock_themselves_out() {
        let me = Uuid::new_v4();
        let admin = user(me, "admin");
        assert!(is_forbidden_self_change(me, &admin, Some("user"), None));
        assert!(is_forbidden_self_change(me, &admin, None, Some(true)));
        assert!(
            !is_forbidden_self_change(me, &admin, Some("admin"), None),
            "same role is a no-op"
        );
        assert!(!is_forbidden_self_change(me, &admin, None, Some(false)));
        assert!(!is_forbidden_self_change(me, &admin, None, None));

        let other = user(Uuid::new_v4(), "admin");
        assert!(
            !is_forbidden_self_change(me, &other, Some("user"), Some(true)),
            "others are fine"
        );
    }
}
