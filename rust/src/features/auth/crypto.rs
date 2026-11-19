//! Pure, security-relevant pieces of auth: passwords, opaque tokens, JWTs.

use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::{Result, anyhow};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::platform::error::{AppError, AppResult};

// ---------- passwords ----------

fn argon2() -> Argon2<'static> {
    // SPEC 4: argon2id, m=19456 KiB, t=2, p=1.
    let params = Params::new(19_456, 2, 1, None).expect("static argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// PHC string (`$argon2id$v=19$m=19456,t=2,p=1$...`) with a random salt. CPU heavy: call from
/// `spawn_blocking`.
pub fn hash_password(password: &str) -> Result<String> {
    Ok(argon2()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("hashing password: {e}"))?
        .to_string())
}

/// False for a wrong password and for a malformed stored hash alike. CPU heavy.
pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|parsed| {
        argon2()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Longest password argon2 ever sees on login / change-password (SPEC 4: 15-128 code points).
pub const PASSWORD_MAX: usize = 128;

/// Bounds argon2 work (19 MiB and a core per run) to `slots` concurrent runs with at most
/// `4 x slots` callers waiting; beyond that callers get 429 `Retry-After: 1`.
pub struct Argon2Pool {
    slots: Arc<Semaphore>,
    waiting: AtomicUsize,
    max_waiting: usize,
}

struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Argon2Pool {
    pub fn new(slots: usize) -> Self {
        let slots = slots.max(1);
        Self {
            slots: Arc::new(Semaphore::new(slots)),
            waiting: AtomicUsize::new(0),
            max_waiting: 4 * slots,
        }
    }

    /// The permit moves into the blocking closure, so it is held for the whole hash even if the
    /// request is cancelled meanwhile; the wait itself is cancellable (dropping the future stops it).
    pub async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> AppResult<T> {
        let permit = match self.slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.max_waiting {
                    self.waiting.fetch_sub(1, Ordering::SeqCst);
                    return Err(AppError::RateLimited { retry_after: 1 });
                }
                let _waiting = Waiting(&self.waiting);
                self.slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(anyhow::Error::from)?
            }
        };
        let handle = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        });
        Ok(handle.await.map_err(anyhow::Error::from)?)
    }
}

static ARGON2: LazyLock<Argon2Pool> =
    LazyLock::new(|| Argon2Pool::new(std::thread::available_parallelism().map_or(2, |n| n.get())));

pub async fn hash_password_async(password: String) -> AppResult<String> {
    Ok(ARGON2.run(move || hash_password(&password)).await??)
}

/// A password longer than `PASSWORD_MAX` never reaches argon2 as itself: the dummy hash is
/// verified instead (same cost) and the answer is `false`.
pub async fn verify_password_async(password: String, phc: String, dummy: &str) -> AppResult<bool> {
    if password.chars().count() > PASSWORD_MAX {
        let dummy = dummy.to_owned();
        ARGON2
            .run(move || verify_password("dummy-password", &dummy))
            .await?;
        return Ok(false);
    }
    ARGON2.run(move || verify_password(&password, &phc)).await
}

// ---------- opaque tokens ----------

/// 32 bytes from the OS-seeded CSPRNG, base64url without padding (43 chars).
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// What the database stores for any opaque token: sha256 hex.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Reuse detection: only a hash equal to the session's previous one proves the presented secret
/// was really issued and already rotated. Anything else (never rotated, a guess) revokes nothing.
pub fn is_replay(previous: Option<&str>, presented: &str) -> bool {
    previous.is_some_and(|p| constant_time_eq(p, presented))
}

/// New refresh token `<session_id>.<secret>`; returns the token and the hash of its secret.
pub fn new_refresh_token(session_id: Uuid) -> (String, String) {
    let secret = random_token();
    let hash = hash_token(&secret);
    (format!("{session_id}.{secret}"), hash)
}

/// Well-formed = `<canonical 36-char uuid>.<43 base64url chars>` (SPEC 4). The secret is returned
/// as transmitted; its hash is taken over that string, not over the decoded bytes.
pub fn parse_refresh_token(token: &str) -> Option<(Uuid, &str)> {
    let (sid, secret) = token.split_once('.')?;
    let canonical_sid = sid.len() == 36
        && sid.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        });
    let base64url = secret.len() == 43
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !(canonical_sid && base64url) {
        return None;
    }
    Some((Uuid::parse_str(sid).ok()?, secret))
}

// ---------- access tokens ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub iat: i64,
    pub exp: i64,
}

pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    ttl: i64,
}

impl JwtKeys {
    pub fn new(secret: &str, ttl: i64) -> Result<Self> {
        // Pinned to HS256: `none` and every other alg fail; `exp` must be present and in the future.
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_required_spec_claims(&["exp", "sub"]);
        validation.validate_exp = true;
        validation.leeway = 0;
        Ok(Self {
            encoding: EncodingKey::from_secret(secret.as_bytes())?,
            decoding: DecodingKey::from_secret(secret.as_bytes())?,
            validation,
            ttl,
        })
    }

    pub fn issue(&self, user_id: Uuid, session_id: Uuid) -> Result<String> {
        let iat = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user_id,
            sid: session_id,
            iat,
            exp: iat + self.ttl,
        };
        Ok(encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &self.encoding,
        )?)
    }

    pub fn verify(&self, token: &str) -> Option<Claims> {
        decode::<Claims>(token, &self.decoding, &self.validation)
            .ok()
            .map(|data| data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_and_verify() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(verify_password("correct horse battery", &phc));
        assert!(!verify_password("correct horse batterY", &phc));
        assert!(!verify_password(
            "correct horse battery",
            "not a phc string"
        ));
        assert_ne!(
            phc,
            hash_password("correct horse battery").unwrap(),
            "salted"
        );
    }

    #[test]
    fn random_tokens_are_32_bytes_and_unique() {
        let a = random_token();
        assert_eq!(a.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
        assert_ne!(a, random_token());
    }

    #[test]
    fn token_hash_is_sha256_hex() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(constant_time_eq(&hash_token("x"), &hash_token("x")));
        assert!(!constant_time_eq(&hash_token("x"), &hash_token("y")));
    }

    #[test]
    fn refresh_token_round_trip_and_rejects_garbage() {
        let sid = Uuid::new_v4();
        let (token, hash) = new_refresh_token(sid);
        let (parsed_sid, secret) = parse_refresh_token(&token).unwrap();
        assert_eq!(parsed_sid, sid);
        assert_eq!(hash_token(secret), hash);
        for bad in [
            "nope".to_owned(),
            "a.b".to_owned(),
            format!("not-a-uuid.{}", "A".repeat(43)),
            format!("{sid}.{}", "A".repeat(42)),
            format!("{sid}.{}==", "A".repeat(43)),
            format!("{}.{}", sid.simple(), random_token()),
            format!("{}.{}", sid.to_string().to_uppercase(), random_token()),
            format!("{sid}.{}+", "A".repeat(42)),
            format!("{sid}.{}.x", random_token()),
        ] {
            assert!(parse_refresh_token(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn jwt_is_hs256_only_and_expires() {
        let keys = JwtKeys::new(&"k".repeat(32), 900).unwrap();
        let (uid, sid) = (Uuid::new_v4(), Uuid::new_v4());
        let token = keys.issue(uid, sid).unwrap();
        let claims = keys.verify(&token).unwrap();
        assert_eq!(
            (claims.sub, claims.sid, claims.exp - claims.iat),
            (uid, sid, 900)
        );

        let payload = token.split('.').nth(1).unwrap();
        let none = format!(
            "{}.{payload}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#)
        );
        assert!(keys.verify(&none).is_none(), "alg=none");

        let other = JwtKeys::new(&"z".repeat(32), 900).unwrap();
        assert!(other.verify(&token).is_none(), "wrong key");

        let expired = JwtKeys::new(&"k".repeat(32), -1)
            .unwrap()
            .issue(uid, sid)
            .unwrap();
        assert!(keys.verify(&expired).is_none(), "expired");

        let hs512 = encode(
            &Header::new(jsonwebtoken::Algorithm::HS512),
            &Claims {
                sub: uid,
                sid,
                iat: 0,
                exp: i64::MAX / 2,
            },
            &EncodingKey::from_secret("k".repeat(32).as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(keys.verify(&hs512).is_none(), "other HMAC alg");
    }

    #[test]
    fn reuse_is_only_the_genuinely_previous_hash() {
        let (old, new) = (hash_token("old-secret"), hash_token("new-secret"));
        assert!(is_replay(Some(&old), &old), "replayed rotated token");
        assert!(
            !is_replay(Some(&old), &hash_token("a guess")),
            "guess after rotation"
        );
        assert!(!is_replay(None, &old), "never rotated: nothing to replay");
        assert!(!is_replay(Some(&old), &new));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn argon2_pool_holds_the_slot_and_caps_waiters() {
        let pool = Arc::new(Argon2Pool::new(1)); // 1 slot, 4 waiters
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let p = pool.clone();
        let running = tokio::spawn(async move {
            p.run(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await
        });
        started_rx.await.unwrap();
        // Cancelling the request does not free the slot while the hash still runs.
        running.abort();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(pool.slots.available_permits(), 0);

        let mut waiters = Vec::new();
        for _ in 0..4 {
            let p = pool.clone();
            waiters.push(tokio::spawn(async move { p.run(|| ()).await }));
        }
        while pool.waiting.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(matches!(
            pool.run(|| ()).await,
            Err(AppError::RateLimited { retry_after: 1 })
        ));

        // A cancelled waiter gives its waiting place back.
        waiters.pop().unwrap().abort();
        while pool.waiting.load(Ordering::SeqCst) != 3 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        release_tx.send(()).unwrap();
        for w in waiters {
            assert!(w.await.unwrap().is_ok());
        }
        assert_eq!(pool.waiting.load(Ordering::SeqCst), 0);
        assert_eq!(pool.slots.available_permits(), 1);
    }
}
