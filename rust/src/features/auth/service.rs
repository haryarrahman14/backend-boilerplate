//! Auth flows (SPEC section 4). Handlers validate input; everything here assumes valid input.

use std::net::IpAddr;

use uuid::Uuid;

use super::{
    crypto,
    dto::TokensResponse,
    guard::AuthUser,
    repo::{self, EMAIL_VERIFICATION, NewSession, PASSWORD_RESET},
};
use crate::{
    features::users::repo::{self as users, User},
    platform::{
        AppState,
        error::{AppError, AppResult},
        validate::is_valid_email,
    },
};

const VERIFY_TTL_SECONDS: i64 = 24 * 3600;
const RESET_TTL_SECONDS: i64 = 3600;
const USER_AGENT_MAX: usize = 255;

pub async fn register(
    state: &AppState,
    email: String,
    password: String,
    name: String,
) -> AppResult<User> {
    let hash = crypto::hash_password_async(password).await?;
    let mut tx = state.db.begin().await?;
    let user = users::create(&mut *tx, &email, &hash, &name)
        .await?
        .ok_or(AppError::EmailTaken)?;
    let token = new_one_time_token(
        state,
        &mut tx,
        user.id,
        EMAIL_VERIFICATION,
        VERIFY_TTL_SECONDS,
    )
    .await?;
    tx.commit().await?;
    if let Some(token) = token {
        let (subject, body) = verification_mail(state, &token);
        state
            .mailer
            .send_in_background(user.email.clone(), subject, body);
    }
    Ok(user)
}

pub async fn login(
    state: &AppState,
    email: &str,
    password: String,
    user_agent: Option<&str>,
    ip: Option<IpAddr>,
) -> AppResult<TokensResponse> {
    let dummy = &state.dummy_hash;
    // An address that could never have been registered (also: NUL bytes Postgres would reject)
    // is a plain miss without a lookup; it still pays for one argon2 verify like every miss.
    if !is_valid_email(email) {
        crypto::verify_password_async(password, dummy.clone(), dummy).await?;
        return Err(AppError::InvalidCredentials);
    }
    let user = users::find_by_email(&state.db, email).await?;
    // Unknown email still pays for one argon2 verify, so timing does not reveal accounts.
    let phc = user
        .as_ref()
        .map_or_else(|| dummy.clone(), |u| u.password_hash.clone());
    let valid = crypto::verify_password_async(password, phc, dummy).await?;
    let user = match user {
        Some(u) if valid => u,
        _ => return Err(AppError::InvalidCredentials),
    };
    after_password_verified(
        user.disabled_at.is_some(),
        state.config.require_verified_email,
        user.email_verified_at.is_some(),
    )?;

    let session_id = Uuid::new_v4();
    let (refresh_token, refresh_hash) = crypto::new_refresh_token(session_id);
    let user_agent = user_agent.map(|ua| match ua.char_indices().nth(USER_AGENT_MAX) {
        Some((cut, _)) => &ua[..cut],
        None => ua,
    });
    let session = NewSession {
        id: session_id,
        user_id: user.id,
        refresh_token_hash: &refresh_hash,
        user_agent,
        ip: ip.map(|ip| ip.to_string()),
        ttl_seconds: state.config.refresh_token_ttl,
    };
    // Bound to the hash that was verified: a reset/change that landed while argon2 ran wins.
    if !repo::create_session(&state.db, session, &user.password_hash).await? {
        return Err(AppError::InvalidCredentials);
    }
    tokens(state, user, session_id, refresh_token)
}

pub async fn refresh(state: &AppState, token: &str) -> AppResult<TokensResponse> {
    let (session_id, secret) = crypto::parse_refresh_token(token).ok_or(AppError::Unauthorized)?;
    let old_hash = crypto::hash_token(secret);
    let (new_token, new_hash) = crypto::new_refresh_token(session_id);

    let ttl = state.config.refresh_token_ttl;
    if let Some(user) =
        repo::rotate_refresh(&state.db, session_id, &old_hash, &new_hash, ttl).await?
    {
        return tokens(state, user, session_id, new_token);
    }
    // Nothing rotated. Only the genuinely previous secret proves a replay of a rotated token;
    // the session id is public, so a guessed secret must not be able to log anyone out.
    let previous = repo::previous_refresh_hash(&state.db, session_id).await?;
    if crypto::is_replay(previous.as_deref(), &old_hash)
        && repo::revoke_replayed_session(&state.db, session_id, &old_hash).await?
    {
        tracing::warn!(session_id = %session_id, "refresh token reuse detected, session revoked");
    }
    Err(AppError::Unauthorized)
}

pub async fn verify_email(state: &AppState, token: &str) -> AppResult<()> {
    let mut tx = state.db.begin().await?;
    let user_id = repo::consume_token(&mut *tx, &crypto::hash_token(token), EMAIL_VERIFICATION)
        .await?
        .ok_or(AppError::InvalidToken)?;
    // Consuming one link kills the user's other verification links (issuing never does).
    repo::burn_tokens(&mut *tx, user_id, EMAIL_VERIFICATION).await?;
    users::mark_verified(&mut *tx, user_id).await?;
    tx.commit().await?;
    Ok(())
}

/// Always "succeeds"; the lookup and the mail happen on a background task so neither the
/// response nor its timing depends on whether the account exists.
pub fn resend_verification(state: &AppState, email: String) {
    let state = state.clone();
    let mailer = state.mailer.clone();
    mailer.spawn_job("resend verification", async move {
        if let Some(user) = users::find_by_email(&state.db, &email).await?
            && user.email_verified_at.is_none()
            && user.disabled_at.is_none()
        {
            let mut tx = state.db.begin().await?;
            let token = new_one_time_token(
                &state,
                &mut tx,
                user.id,
                EMAIL_VERIFICATION,
                VERIFY_TTL_SECONDS,
            )
            .await?;
            tx.commit().await?;
            if let Some(token) = token {
                let (subject, body) = verification_mail(&state, &token);
                state.mailer.send(&user.email, subject, body).await?;
            }
        }
        Ok(())
    });
}

/// Same no-enumeration shape as `resend_verification`.
pub fn forgot_password(state: &AppState, email: String) {
    let state = state.clone();
    let mailer = state.mailer.clone();
    mailer.spawn_job("forgot password", async move {
        // A disabled account gets no recovery mail; the public answer stays 202.
        if let Some(user) = users::find_by_email(&state.db, &email).await?
            && user.disabled_at.is_none()
        {
            let mut tx = state.db.begin().await?;
            let token =
                new_one_time_token(&state, &mut tx, user.id, PASSWORD_RESET, RESET_TTL_SECONDS)
                    .await?;
            tx.commit().await?;
            let Some(token) = token else { return Ok(()) };
            // The transaction is committed: no DB connection is held during the SMTP send.
            let (subject, body) = reset_mail(&state, &token);
            state.mailer.send(&user.email, subject, body).await?;
        }
        Ok(())
    });
}

/// One transaction, in the lock order user_tokens -> users -> sessions: consume the token, burn
/// the other reset tokens, set hash + verified email, revoke every session. The new password is
/// validated (by the handler) and hashed before the transaction opens.
pub async fn reset_password(state: &AppState, token: &str, password: String) -> AppResult<()> {
    let hash = crypto::hash_password_async(password).await?;
    let mut tx = state.db.begin().await?;
    let user_id = repo::consume_token(&mut *tx, &crypto::hash_token(token), PASSWORD_RESET)
        .await?
        .ok_or(AppError::InvalidToken)?;
    repo::burn_tokens(&mut *tx, user_id, PASSWORD_RESET).await?;
    users::set_password_and_verify(&mut *tx, user_id, &hash).await?;
    repo::revoke_user_sessions(&mut *tx, user_id, None).await?;
    tx.commit().await?;
    Ok(())
}

/// Lock order users -> sessions. The hash write is a compare-and-swap against the hash that was
/// verified, so a reset that lands meanwhile can never be silently overwritten (a stolen session
/// plus the old password must not beat the victim's reset). Reset tokens are left alone: the
/// mailbox owner must always be able to recover.
pub async fn change_password(
    state: &AppState,
    auth: &AuthUser,
    current: String,
    new: String,
) -> AppResult<()> {
    let verified_hash = auth.user.password_hash.clone();
    if !crypto::verify_password_async(current, verified_hash.clone(), &state.dummy_hash).await? {
        return Err(AppError::InvalidCredentials);
    }
    let hash = crypto::hash_password_async(new).await?;
    let mut tx = state.db.begin().await?;
    if !repo::swap_password_hash(
        &mut *tx,
        auth.user.id,
        &verified_hash,
        &hash,
        auth.session_id,
    )
    .await?
    {
        tx.rollback().await?;
        return Err(AppError::InvalidCredentials);
    }
    repo::revoke_user_sessions(&mut *tx, auth.user.id, Some(auth.session_id)).await?;
    tx.commit().await?;
    Ok(())
}

fn tokens(
    state: &AppState,
    user: User,
    session_id: Uuid,
    refresh_token: String,
) -> AppResult<TokensResponse> {
    Ok(TokensResponse {
        access_token: state.jwt.issue(user.id, session_id)?,
        refresh_token,
        token_type: "Bearer",
        expires_in: state.config.access_token_ttl,
        user: user.into(),
    })
}

/// `None` while the cooldown (EMAIL_TOKEN_COOLDOWN_SECONDS) is running: nothing issued or sent.
async fn new_one_time_token(
    state: &AppState,
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
    kind: &str,
    ttl_seconds: i64,
) -> sqlx::Result<Option<String>> {
    let token = crypto::random_token();
    let hash = crypto::hash_token(&token);
    let cooldown = state.config.email_token_cooldown;
    let issued = repo::issue_token(tx, user_id, kind, &hash, ttl_seconds, cooldown).await?;
    Ok(issued.then_some(token))
}

// Mail bodies are fixed text plus the link only: nothing a registrant typed (anyone can register
// any address and would otherwise send their own text from our domain).

fn verification_mail(state: &AppState, token: &str) -> (&'static str, String) {
    let link = format!("{}/verify-email?token={token}", state.config.app_url);
    (
        "Verify your email address",
        format!(
            "Confirm your email address by opening this link (valid for 24 hours):\n{link}\n\n\
             If you did not create this account, ignore this email and do not use the link."
        ),
    )
}

fn reset_mail(state: &AppState, token: &str) -> (&'static str, String) {
    let link = format!("{}/reset-password?token={token}", state.config.app_url);
    (
        "Reset your password",
        format!(
            "Someone asked to reset the password of your account.\n\n\
             Choose a new password here (the link works once and expires in 1 hour):\n{link}\n\n\
             If it was not you, ignore this email; your password stays the same."
        ),
    )
}

/// What login answers once the password is known to be right. Only then may the account state
/// show (a wrong password is always 401, so these statuses are no enumeration oracle).
pub fn after_password_verified(
    disabled: bool,
    require_verified: bool,
    verified: bool,
) -> AppResult<()> {
    if disabled {
        return Err(AppError::AccountDisabled);
    }
    if require_verified && !verified {
        return Err(AppError::EmailNotVerified);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_wins_after_the_password_verified() {
        assert!(after_password_verified(false, false, false).is_ok());
        assert!(after_password_verified(false, true, true).is_ok());
        assert!(matches!(
            after_password_verified(true, false, true),
            Err(AppError::AccountDisabled)
        ));
        assert!(matches!(
            after_password_verified(true, true, false),
            Err(AppError::AccountDisabled)
        ));
        assert!(matches!(
            after_password_verified(false, true, false),
            Err(AppError::EmailNotVerified)
        ));
    }
}
