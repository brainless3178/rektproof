//! Security utilities for the analyzer
//!
//! Provides secure handling of sensitive data like API keys,
//! sandboxing considerations, and input validation.

use std::fmt;
use zeroize::Zeroize;

/// A secret value that won't be accidentally logged or printed.
///
/// The inner value is zeroed on drop for additional security.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Create a new secret value
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Expose the secret value (use sparingly)
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl Secret<String> {
    /// Create from environment variable
    pub fn from_env(key: &str) -> Option<Self> {
        std::env::var(key).ok().map(Secret::new)
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret([REDACTED])")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Input validation utilities
pub mod validation {
    use std::path::Path;

    /// Maximum source file size (10 MB)
    pub const MAX_SOURCE_SIZE: usize = 10 * 1024 * 1024;

    /// Maximum path depth to prevent traversal attacks
    pub const MAX_PATH_DEPTH: usize = 50;

    /// Validate source code input
    pub fn validate_source(source: &str) -> Result<(), ValidationError> {
        if source.len() > MAX_SOURCE_SIZE {
            return Err(ValidationError::TooLarge {
                size: source.len(),
                max: MAX_SOURCE_SIZE,
            });
        }

        // Check for null bytes (potential injection)
        if source.contains('\0') {
            return Err(ValidationError::InvalidCharacter('\0'));
        }

        Ok(())
    }

    /// Validate file path (prevent traversal)
    pub fn validate_path(path: &Path) -> Result<(), ValidationError> {
        // Check for path traversal attempts
        let path_str = path.to_string_lossy();
        if path_str.contains("..") {
            return Err(ValidationError::PathTraversal);
        }

        // Check depth
        let depth = path.components().count();
        if depth > MAX_PATH_DEPTH {
            return Err(ValidationError::TooDeep {
                depth,
                max: MAX_PATH_DEPTH,
            });
        }

        Ok(())
    }

    /// Validation errors
    #[derive(Debug)]
    pub enum ValidationError {
        TooLarge { size: usize, max: usize },
        TooDeep { depth: usize, max: usize },
        InvalidCharacter(char),
        PathTraversal,
    }

    impl std::fmt::Display for ValidationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::TooLarge { size, max } => {
                    write!(f, "Input too large: {} bytes (max: {})", size, max)
                }
                Self::TooDeep { depth, max } => {
                    write!(f, "Path too deep: {} levels (max: {})", depth, max)
                }
                Self::InvalidCharacter(c) => {
                    write!(f, "Invalid character in input: {:?}", c)
                }
                Self::PathTraversal => {
                    write!(f, "Path traversal attempt detected")
                }
            }
        }
    }

    impl std::error::Error for ValidationError {}
}

pub mod sandbox {
    //! # Analysis Sandboxing
    //!
    //! Provides resource-limit guards to prevent untrusted code analysis
    //! from consuming unbounded CPU or memory.

    use std::time::{Duration, Instant};

    /// A guard that enforces a wall-clock timeout on analysis.
    ///
    /// Create with a `Duration`, then periodically call `check()` inside
    /// long-running loops.  Returns `Err` if time is up.
    pub struct SandboxGuard {
        start: Instant,
        timeout: Duration,
        max_memory_bytes: usize,
    }

    impl SandboxGuard {
        /// Create a new sandbox guard.
        ///
        /// * `timeout` – abort if analysis exceeds this wall-clock time.
        /// * `max_memory_bytes` – advisory memory cap (checked on `check()`).
        pub fn new(timeout: Duration, max_memory_bytes: usize) -> Self {
            Self {
                start: Instant::now(),
                timeout,
                max_memory_bytes,
            }
        }

        /// Default guard: 120 s wall-clock, 2 GB memory.
        pub fn default_limits() -> Self {
            Self::new(Duration::from_secs(120), 2 * 1024 * 1024 * 1024)
        }

        /// Check whether the analysis has exceeded its resource budget.
        pub fn check(&self) -> Result<(), SandboxError> {
            if self.start.elapsed() > self.timeout {
                return Err(SandboxError::Timeout {
                    elapsed: self.start.elapsed(),
                    limit: self.timeout,
                });
            }
            // Best-effort resident-size check (Linux only).
            #[cfg(target_os = "linux")]
            {
                if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                    for line in status.lines() {
                        if line.starts_with("VmRSS:") {
                            let kb: usize = line.split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            if kb * 1024 > self.max_memory_bytes {
                                return Err(SandboxError::MemoryExceeded {
                                    used_bytes: kb * 1024,
                                    limit_bytes: self.max_memory_bytes,
                                });
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        /// Elapsed wall-clock time since guard creation.
        pub fn elapsed(&self) -> Duration {
            self.start.elapsed()
        }
    }

    /// Sandbox errors.
    #[derive(Debug)]
    pub enum SandboxError {
        Timeout { elapsed: Duration, limit: Duration },
        MemoryExceeded { used_bytes: usize, limit_bytes: usize },
    }

    impl std::fmt::Display for SandboxError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Timeout { elapsed, limit } => {
                    write!(f, "Analysis timeout: {:.1}s exceeded {:.1}s limit",
                           elapsed.as_secs_f64(), limit.as_secs_f64())
                }
                Self::MemoryExceeded { used_bytes, limit_bytes } => {
                    write!(f, "Memory limit exceeded: {} MB used (limit: {} MB)",
                           used_bytes / (1024 * 1024), limit_bytes / (1024 * 1024))
                }
            }
        }
    }

    impl std::error::Error for SandboxError {}
}

/// Rate limiting for LLM API calls
pub struct RateLimiter {
    /// Requests per minute
    rpm_limit: u32,
    /// Current count
    request_count: std::sync::atomic::AtomicU32,
    /// Last reset time
    last_reset: std::sync::RwLock<std::time::Instant>,
}

impl RateLimiter {
    pub fn new(rpm_limit: u32) -> Self {
        Self {
            rpm_limit,
            request_count: std::sync::atomic::AtomicU32::new(0),
            last_reset: std::sync::RwLock::new(std::time::Instant::now()),
        }
    }

    /// Check if a request is allowed
    pub fn check(&self) -> bool {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let now = std::time::Instant::now();
        let last = match self.last_reset.read() {
            Ok(l) => *l,
            Err(_) => return true, // fail open on poison
        };

        // Reset counter every minute
        if now.duration_since(last) > Duration::from_secs(60) {
            if let Ok(mut w) = self.last_reset.write() {
                *w = now;
            }
            self.request_count.store(0, Ordering::Relaxed);
        }

        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        count < self.rpm_limit
    }

    /// Wait until request is allowed
    pub fn wait(&self) {
        use std::time::Duration;

        while !self.check() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_redaction() {
        let secret = Secret::new("super-secret-key".to_string());

        // Debug should not expose value
        let debug = format!("{:?}", secret);
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("REDACTED"));

        // Display should not expose value
        let display = format!("{}", secret);
        assert!(!display.contains("super-secret"));
        assert!(display.contains("REDACTED"));

        // Can still access value when needed
        assert_eq!(secret.expose(), "super-secret-key");
    }

    #[test]
    fn test_validation_source() {
        use validation::*;

        // Normal source is OK
        assert!(validate_source("fn main() {}").is_ok());

        // Null bytes are rejected
        assert!(matches!(
            validate_source("fn main() {\0}"),
            Err(ValidationError::InvalidCharacter('\0'))
        ));
    }

    #[test]
    fn test_validation_path() {
        use std::path::Path;
        use validation::*;

        // Normal path is OK
        assert!(validate_path(Path::new("/home/user/project/src/lib.rs")).is_ok());

        // Path traversal is rejected
        assert!(matches!(
            validate_path(Path::new("/home/user/../../../etc/passwd")),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5);

        // First 5 requests should pass
        for _ in 0..5 {
            assert!(limiter.check());
        }

        // 6th request should fail (within same minute)
        assert!(!limiter.check());
    }
}
