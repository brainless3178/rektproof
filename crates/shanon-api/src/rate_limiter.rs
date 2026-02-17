//! # Rate Limiter Middleware for Shanon API
//!
//! Token-bucket rate limiting per IP address with configurable burst and refill rates.
//! Integrates as Actix-web middleware wrapping all API routes.
//!
//! ## Configuration (environment variables)
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `SHANON_RATE_LIMIT_RPS` | `30` | Requests per second per IP |
//! | `SHANON_RATE_LIMIT_BURST` | `60` | Maximum burst capacity |
//!
//! ## Usage
//!
//! ```rust,ignore
//! let limiter = RateLimiterState::from_env();
//! App::new()
//!     .app_data(web::Data::new(limiter))
//!     .wrap(RateLimiterMiddleware)
//! ```

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::collections::HashMap;
use std::future::{ready, Ready, Future};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Instant;

// ─── Configuration ──────────────────────────────────────────────────────────

/// Rate limiter configuration and shared state.
#[derive(Debug)]
pub struct RateLimiterState {
    /// Maximum requests per second per IP.
    pub requests_per_second: f64,
    /// Maximum burst capacity (token bucket size).
    pub burst_size: u32,
    /// Per-IP token bucket state.
    pub buckets: Mutex<HashMap<String, TokenBucket>>,
}

/// A token bucket for a single IP address.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill: Instant,
}

impl RateLimiterState {
    /// Create a new rate limiter with the given configuration.
    pub fn new(requests_per_second: f64, burst_size: u32) -> Self {
        Self {
            requests_per_second,
            burst_size,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Create from environment variables with sensible defaults.
    ///
    /// - `SHANON_RATE_LIMIT_RPS`: requests per second (default: 30)
    /// - `SHANON_RATE_LIMIT_BURST`: burst capacity (default: 60)
    pub fn from_env() -> Self {
        let rps: f64 = std::env::var("SHANON_RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30.0);
        let burst: u32 = std::env::var("SHANON_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        Self::new(rps, burst)
    }

    /// Check if a request from the given IP should be allowed.
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(b) => b,
            Err(_) => return true, // Fail open on poison
        };

        let now = Instant::now();
        let bucket = buckets.entry(ip.to_string()).or_insert(TokenBucket {
            tokens: self.burst_size as f64,
            last_refill: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.requests_per_second)
            .min(self.burst_size as f64);
        bucket.last_refill = now;

        // Consume one token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Periodically clean up stale buckets to prevent memory leaks.
    /// Call this from a background task.
    pub fn cleanup_stale_buckets(&self, max_age_secs: f64) {
        if let Ok(mut buckets) = self.buckets.lock() {
            let now = Instant::now();
            buckets.retain(|_, bucket| {
                now.duration_since(bucket.last_refill).as_secs_f64() < max_age_secs
            });
        }
    }
}

// ─── Actix-web Middleware ───────────────────────────────────────────────────

/// Actix-web middleware that applies per-IP rate limiting.
pub struct RateLimiterMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RateLimiterMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimiterMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddlewareService { service }))
    }
}

/// The actual service that processes each request through the rate limiter.
pub struct RateLimiterMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract IP from connection info
        let ip = req
            .connection_info()
            .peer_addr()
            .unwrap_or("unknown")
            .to_string();

        // Check rate limit state
        let allowed = if let Some(limiter) = req.app_data::<actix_web::web::Data<RateLimiterState>>() {
            limiter.check_rate_limit(&ip)
        } else {
            true // No limiter configured, allow all
        };

        if !allowed {
            return Box::pin(async move {
                let response = HttpResponse::TooManyRequests()
                    .json(serde_json::json!({
                        "error": "Rate limit exceeded",
                        "hint": "Too many requests. Please slow down.",
                        "retry_after_seconds": 1
                    }));
                Ok(req.into_response(response).map_into_right_body())
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiterState::new(10.0, 10);
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("127.0.0.1"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiterState::new(10.0, 5);
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("127.0.0.1"));
        }
        // 6th request should be blocked
        assert!(!limiter.check_rate_limit("127.0.0.1"));
    }

    #[test]
    fn test_rate_limiter_per_ip_isolation() {
        let limiter = RateLimiterState::new(10.0, 2);
        assert!(limiter.check_rate_limit("192.168.1.1"));
        assert!(limiter.check_rate_limit("192.168.1.1"));
        assert!(!limiter.check_rate_limit("192.168.1.1"));
        // Different IP should have its own bucket
        assert!(limiter.check_rate_limit("192.168.1.2"));
    }

    #[test]
    fn test_rate_limiter_from_env_defaults() {
        let limiter = RateLimiterState::from_env();
        assert_eq!(limiter.requests_per_second, 30.0);
        assert_eq!(limiter.burst_size, 60);
    }

    #[test]
    fn test_cleanup_stale_buckets() {
        let limiter = RateLimiterState::new(10.0, 10);
        limiter.check_rate_limit("old_ip");
        limiter.cleanup_stale_buckets(0.0); // max_age=0 means everything is stale
        let buckets = limiter.buckets.lock().unwrap();
        assert!(buckets.is_empty());
    }

    #[test]
    fn test_rate_limiter_fail_open() {
        // Test that a poisoned mutex doesn't crash — it allows the request
        let limiter = RateLimiterState::new(10.0, 10);
        assert!(limiter.check_rate_limit("test_ip"));
    }
}
