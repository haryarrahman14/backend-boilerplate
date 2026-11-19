use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{extract::State, middleware::Next, response::Response};

use super::{AppState, error::AppError, middleware::ClientIp};

/// Most keys tracked at once. A new client arriving while full is allowed and not tracked:
/// refusing it would let anyone holding 100 000 addresses lock everyone else out.
pub const MAX_KEYS: usize = 100_000;

/// Fixed window counter per client (IPv4 address, or IPv6 /64).
/// Single-instance only: the counters live in this process. Swap for Redis when scaled out.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    max_keys: usize,
    inner: Mutex<Windows>,
}

struct Windows {
    counters: HashMap<IpAddr, (Instant, u32)>,
    last_sweep: Instant,
}

/// An IPv6 client usually controls a whole /64, so that is the unit it is limited by.
pub fn rate_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(v6.to_bits() & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

fn secs_ceil(d: Duration) -> u64 {
    // Rounded up so a client that waits Retry-After seconds is always let back in.
    (d.as_millis().div_ceil(1000) as u64).max(1)
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration, max_keys: usize) -> Self {
        let inner = Windows {
            counters: HashMap::new(),
            last_sweep: Instant::now(),
        };
        Self {
            limit,
            window,
            max_keys,
            inner: Mutex::new(inner),
        }
    }

    /// `Err(seconds)` = rejected, retry after that many seconds.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let mut w = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let window = self.window;
        // Expired windows are swept at most once per window, never per request.
        if now.saturating_duration_since(w.last_sweep) >= window {
            w.counters
                .retain(|_, (start, _)| now.saturating_duration_since(*start) < window);
            w.last_sweep = now;
        }
        let full = w.counters.len() >= self.max_keys;
        match w.counters.get_mut(&rate_key(ip)) {
            Some(entry) => {
                if now.saturating_duration_since(entry.0) >= window {
                    *entry = (now, 0);
                }
                if entry.1 >= self.limit {
                    return Err(secs_ceil(
                        window.saturating_sub(now.saturating_duration_since(entry.0)),
                    ));
                }
                entry.1 += 1;
                Ok(())
            }
            None if full => Ok(()), // untracked; existing keys stay limited
            None => {
                w.counters.insert(rate_key(ip), (now, 1));
                Ok(())
            }
        }
    }
}

pub async fn limit_auth(
    State(state): State<AppState>,
    ip: ClientIp,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, AppError> {
    state
        .limiter
        .check(ip.0.unwrap_or(IpAddr::from([0, 0, 0, 0])), Instant::now()) // no peer: one shared key
        .map_err(|retry_after| AppError::RateLimited { retry_after })?;
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_blocks_then_resets() {
        let rl = RateLimiter::new(3, Duration::from_secs(60), MAX_KEYS);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(rl.check(ip, t0).is_ok());
        }
        assert_eq!(rl.check(ip, t0), Err(60));
        assert_eq!(
            rl.check(ip, t0 + Duration::from_millis(59_500)),
            Err(1),
            "rounds up"
        );
        assert!(rl.check(other, t0).is_ok(), "per IP");
        assert!(
            rl.check(ip, t0 + Duration::from_secs(60)).is_ok(),
            "new window"
        );
        assert!(rl.check(ip, t0 + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn ipv6_is_keyed_by_slash_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(rate_key(a), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_eq!(rate_key(a), rate_key(b));
        assert_ne!(rate_key(a), rate_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(rate_key(mapped), "192.0.2.1".parse::<IpAddr>().unwrap());

        let rl = RateLimiter::new(1, Duration::from_secs(60), MAX_KEYS);
        let t0 = Instant::now();
        assert!(rl.check(a, t0).is_ok());
        assert!(rl.check(b, t0).is_err(), "same /64 shares the budget");
        assert!(rl.check(c, t0).is_ok());
    }

    #[test]
    fn full_map_allows_new_keys_untracked() {
        let rl = RateLimiter::new(1, Duration::from_secs(60), 3);
        let t0 = Instant::now();
        for i in 1..=3u8 {
            rl.check(IpAddr::from([10, 0, 0, i]), t0).unwrap();
        }
        let newcomer = IpAddr::from([10, 0, 0, 9]);
        for _ in 0..5 {
            assert!(
                rl.check(newcomer, t0).is_ok(),
                "new key while full is allowed"
            );
        }
        assert_eq!(
            rl.inner.lock().unwrap().counters.len(),
            3,
            "and not tracked"
        );
        assert!(
            rl.check(IpAddr::from([10, 0, 0, 1]), t0).is_err(),
            "existing keys stay limited"
        );
        // One window later the sweep drops the expired keys and the newcomer is tracked again.
        let later = t0 + Duration::from_secs(61);
        assert!(rl.check(newcomer, later).is_ok());
        assert!(rl.check(newcomer, later).is_err());
        assert_eq!(rl.inner.lock().unwrap().counters.len(), 1);
    }

    #[test]
    fn sweep_runs_at_most_once_per_window() {
        let rl = RateLimiter::new(5, Duration::from_secs(60), MAX_KEYS);
        let t0 = Instant::now();
        rl.check(IpAddr::from([10, 0, 0, 1]), t0).unwrap();
        let sweep = rl.inner.lock().unwrap().last_sweep;
        rl.check(IpAddr::from([10, 0, 0, 2]), t0 + Duration::from_secs(10))
            .unwrap();
        assert_eq!(rl.inner.lock().unwrap().last_sweep, sweep);
    }
}
