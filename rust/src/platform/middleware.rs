use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::Instrument;
use uuid::Uuid;

use super::{AppState, error::AppError};

pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Client IP, always a parsed address (see `client_ip`); `None` only without a socket peer.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("client ip missing").into())
    }
}

/// Filled by the auth guard so the access log line can name the user.
#[derive(Clone, Default)]
pub struct LogUser(Arc<OnceLock<Uuid>>);

impl LogUser {
    pub fn set(&self, id: Uuid) {
        let _ = self.0.set(id);
    }
}

fn valid_request_id(v: &HeaderValue) -> bool {
    let b = v.as_bytes();
    (1..=64).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

/// An address block such as `10.0.0.0/8` or `::1/128`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(raw: &str) -> Option<Cidr> {
        let (addr, prefix) = raw.trim().split_once('/')?;
        let net: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Cidr { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            _ => false,
        }
    }
}

/// `hops = 0`: the socket peer, `X-Forwarded-For` ignored. `hops = N`: the N-th entry from the
/// right of `X-Forwarded-For` (each trusted proxy appends one; the left side is client-written),
/// but only when the peer itself is one of the `proxies`; from anyone else the header is ignored.
/// A missing or unparsable entry falls back to the peer. Entries are split on raw bytes, so a
/// non-ASCII entry spoils only itself. IPv4-mapped IPv6 becomes plain IPv4.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    hops: usize,
    proxies: &[Cidr],
) -> Option<IpAddr> {
    let peer = peer.map(|p| p.to_canonical());
    let trusted_peer = peer.is_some_and(|p| proxies.iter().any(|c| c.contains(p)));
    let forwarded = (hops > 0 && trusted_peer)
        .then(|| {
            // Several X-Forwarded-For headers are one list, in order.
            let entries: Vec<&[u8]> = headers
                .get_all("x-forwarded-for")
                .iter()
                .flat_map(|v| v.as_bytes().split(|b| *b == b','))
                .collect();
            let entry = entries.len().checked_sub(hops).map(|i| entries[i])?;
            std::str::from_utf8(entry)
                .ok()?
                .trim()
                .parse::<IpAddr>()
                .ok()
        })
        .flatten();
    forwarded.map(|ip| ip.to_canonical()).or(peer)
}

/// Outermost layer: request id (echoed or generated), client IP, a span carrying the
/// request id for every log line, and one access log line per request.
pub async fn request_context(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let request_id = req
        .headers()
        .get(&X_REQUEST_ID)
        .filter(|v| valid_request_id(v))
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let cfg = &state.config;
    let ip = client_ip(
        req.headers(),
        peer,
        cfg.trusted_proxy_hops,
        &cfg.trusted_proxy_cidrs,
    );
    let user = LogUser::default();
    req.extensions_mut().insert(ClientIp(ip));
    req.extensions_mut().insert(user.clone());

    let method = req.method().clone();
    // Path only: query strings are never logged.
    let path = req.uri().path().to_owned();
    let span = tracing::info_span!("request", request_id = %request_id);
    let mut res = next.run(req).instrument(span.clone()).await;

    let status = res.status().as_u16();
    let duration_ms = (started.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
    span.in_scope(|| {
        let user_id = user.0.get().map(|id| id.to_string());
        tracing::info!(
            method = %method,
            path = %path,
            status,
            duration_ms,
            request_id = %request_id,
            user_id,
            "request"
        );
    });
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        res.headers_mut().insert(X_REQUEST_ID.clone(), v);
    }
    res
}

/// Whole-request deadline (handler + body read). Slow-header clients are bounded by hyper's own
/// header read timeout.
pub async fn timeout(req: Request, next: Next) -> Response {
    const LIMIT: Duration = Duration::from_secs(30);
    match tokio::time::timeout(LIMIT, next.run(req)).await {
        Ok(res) => res,
        Err(_) => AppError::Timeout.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(values: &[&[u8]]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_bytes(v).unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn local() -> Vec<Cidr> {
        vec![
            Cidr::parse("127.0.0.1/32").unwrap(),
            Cidr::parse("::1/128").unwrap(),
        ]
    }

    #[test]
    fn client_ip_counts_hops_from_the_right() {
        let peer = Some(ip("127.0.0.1"));
        let h = xff(&[b"6.6.6.6, 203.0.113.9"]);
        assert_eq!(
            client_ip(&h, peer, 0, &local()),
            peer,
            "hops=0 ignores the header"
        );
        assert_eq!(client_ip(&h, peer, 1, &local()), Some(ip("203.0.113.9")));
        assert_eq!(client_ip(&h, peer, 2, &local()), Some(ip("6.6.6.6")));
        assert_eq!(client_ip(&h, peer, 3, &local()), peer, "not enough entries");
        assert_eq!(
            client_ip(&xff(&[b"1.1.1.1", b"2.2.2.2"]), peer, 1, &local()),
            Some(ip("2.2.2.2"))
        );
        assert_eq!(client_ip(&HeaderMap::new(), peer, 1, &local()), peer);
    }

    #[test]
    fn client_ip_ignores_forwarded_from_an_untrusted_peer() {
        let h = xff(&[b"203.0.113.9"]);
        let outsider = Some(ip("198.51.100.7"));
        assert_eq!(client_ip(&h, outsider, 1, &local()), outsider);
        assert_eq!(client_ip(&h, outsider, 1, &[]), outsider);
        let proxy = Some(ip("10.1.2.3"));
        assert_eq!(
            client_ip(&h, proxy, 1, &[Cidr::parse("10.0.0.0/8").unwrap()]),
            Some(ip("203.0.113.9"))
        );
        assert_eq!(
            client_ip(&h, None, 1, &local()),
            None,
            "no peer, no placeholder"
        );
    }

    #[test]
    fn client_ip_parses_entry_by_entry_and_canonicalises() {
        let peer = Some(ip("::ffff:127.0.0.1"));
        assert_eq!(
            client_ip(&xff(&[b"not-an-ip"]), peer, 1, &local()),
            Some(ip("127.0.0.1"))
        );
        assert_eq!(
            client_ip(&xff(&[b"1.2.3.4:80"]), peer, 1, &local()),
            Some(ip("127.0.0.1"))
        );
        assert_eq!(
            client_ip(&xff(&[b"::ffff:198.51.100.4"]), peer, 1, &local()),
            Some(ip("198.51.100.4"))
        );
        assert_eq!(
            client_ip(&xff(&[b"2001:db8::1"]), peer, 1, &local()),
            Some(ip("2001:db8::1"))
        );
        // A non-ASCII entry on the left does not discard the whole header.
        let h = xff(&["caf\u{e9}, 203.0.113.5".as_bytes()]);
        assert_eq!(client_ip(&h, peer, 1, &local()), Some(ip("203.0.113.5")));
        assert_eq!(
            client_ip(&h, peer, 2, &local()),
            Some(ip("127.0.0.1")),
            "the bad entry itself falls back"
        );
    }

    #[test]
    fn cidr_parse_and_contains() {
        let net = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(net.contains(ip("192.168.4.5")));
        assert!(net.contains(ip("::ffff:192.168.4.5")));
        assert!(!net.contains(ip("192.169.0.1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(
            Cidr::parse("2001:db8::/32")
                .unwrap()
                .contains(ip("2001:db8:ffff::1"))
        );
        for bad in ["10.0.0.0/33", "10.0.0.0", "::/129", "nope/8", "10.0.0.0/x"] {
            assert_eq!(Cidr::parse(bad), None, "{bad}");
        }
    }
}
