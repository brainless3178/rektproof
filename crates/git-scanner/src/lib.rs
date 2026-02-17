//! Git Scanner - For scanning Git repositories
//!
//! Handles cloning of remote Solana program repositories for automated audits.
//! Supports GitHub, GitLab, Bitbucket, Codeberg, and any public Git host.
//!
//! ## Private Repository Support
//!
//! Set `GITHUB_TOKEN` or `GIT_TOKEN` environment variable to authenticate
//! when cloning private repositories. The token is injected into the HTTPS URL.
//!
//! ```bash
//! export GITHUB_TOKEN=ghp_xxxx
//! ```

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Git clone failed: {0}")]
    CloneFailed(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Authentication error: {0}")]
    AuthError(String),
}

pub struct GitScanner {
    temp_dir: Option<TempDir>,
}

impl GitScanner {
    pub fn new() -> Self {
        Self { temp_dir: None }
    }

    /// Clone a repository from a Git hosting URL and return the local path.
    /// Supports GitHub, GitLab, Bitbucket, Codeberg, and any valid HTTPS git URL.
    /// If `branch` is provided, only that branch is cloned.
    ///
    /// Automatically uses `GITHUB_TOKEN` or `GIT_TOKEN` environment variable
    /// for authentication if available, enabling private repo access.
    pub fn clone_repo(&mut self, repo_url: &str, branch: Option<&str>) -> Result<PathBuf, GitError> {
        let token = std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GIT_TOKEN"))
            .ok();
        self.clone_repo_inner(repo_url, branch, token.as_deref())
    }

    /// Clone a repository with an explicit authentication token.
    ///
    /// The token is injected into the HTTPS URL for authenticated cloning.
    /// For GitHub, use a Personal Access Token (PAT). For GitLab, use a
    /// project access token or deploy token.
    pub fn clone_repo_authenticated(
        &mut self,
        repo_url: &str,
        branch: Option<&str>,
        token: &str,
    ) -> Result<PathBuf, GitError> {
        self.clone_repo_inner(repo_url, branch, Some(token))
    }

    /// Internal clone implementation with optional token injection.
    fn clone_repo_inner(
        &mut self,
        repo_url: &str,
        branch: Option<&str>,
        token: Option<&str>,
    ) -> Result<PathBuf, GitError> {
        // Validate URL
        let url = Url::parse(repo_url).map_err(|e| GitError::InvalidUrl(e.to_string()))?;
        if url.host_str().is_none() {
            return Err(GitError::InvalidUrl(
                "URL must contain a valid host".to_string(),
            ));
        }

        // Inject token into HTTPS URL if provided
        let clone_url = if let Some(tok) = token {
            let mut auth_url = url.clone();
            if auth_url.scheme() == "https" {
                auth_url.set_username("x-access-token").map_err(|_| {
                    GitError::AuthError("Failed to set username in URL".to_string())
                })?;
                auth_url.set_password(Some(tok)).map_err(|_| {
                    GitError::AuthError("Failed to set token in URL".to_string())
                })?;
                auth_url.to_string()
            } else {
                repo_url.to_string()
            }
        } else {
            repo_url.to_string()
        };

        // Create a temporary directory for the clone
        let temp = TempDir::new().map_err(|e| GitError::IoError(e.to_string()))?;
        let path = temp.path().to_path_buf();

        // Execute git clone
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg("--depth").arg("1");
        if let Some(b) = branch {
            cmd.arg("--branch").arg(b);
        }
        let output = cmd
            .arg(&clone_url)
            .arg(&path)
            .output()
            .map_err(|e| GitError::IoError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Sanitize error: don't leak the token
            let sanitized = if token.is_some() {
                stderr.replace(token.unwrap_or(""), "***")
            } else {
                stderr.to_string()
            };
            return Err(GitError::CloneFailed(sanitized));
        }

        // Store temp dir so it doesn't get deleted immediately
        self.temp_dir = Some(temp);

        Ok(path)
    }

    /// Cleanup the temporary directory
    pub fn cleanup(&mut self) {
        self.temp_dir = None;
    }
}

impl Default for GitScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_scanner_creation() {
        let scanner = GitScanner::new();
        assert!(scanner.temp_dir.is_none());
    }

    #[test]
    fn test_git_scanner_default() {
        let scanner = GitScanner::default();
        assert!(scanner.temp_dir.is_none());
    }

    #[test]
    fn test_clone_invalid_url() {
        let mut scanner = GitScanner::new();
        let result = scanner.clone_repo("not-a-valid-url", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            GitError::InvalidUrl(_) => {}
            other => panic!("Expected InvalidUrl, got: {:?}", other),
        }
    }

    #[test]
    fn test_clone_no_host_url() {
        let mut scanner = GitScanner::new();
        let result = scanner.clone_repo("file:///local/path", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            // file:// URLs have no host — clone would fail on validation
            GitError::InvalidUrl(_) | GitError::CloneFailed(_) => {}
            other => panic!("Expected InvalidUrl or CloneFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_cleanup() {
        let mut scanner = GitScanner::new();
        scanner.cleanup();
        assert!(scanner.temp_dir.is_none());
    }

    #[test]
    fn test_error_display() {
        let err = GitError::InvalidUrl("bad url".to_string());
        assert!(err.to_string().contains("bad url"));
        let err = GitError::CloneFailed("failed".to_string());
        assert!(err.to_string().contains("failed"));
        let err = GitError::AuthError("auth failed".to_string());
        assert!(err.to_string().contains("auth failed"));
    }

    #[test]
    fn test_clone_authenticated_invalid_url() {
        let mut scanner = GitScanner::new();
        let result = scanner.clone_repo_authenticated("not-a-url", None, "test-token");
        assert!(result.is_err());
        match result.unwrap_err() {
            GitError::InvalidUrl(_) => {}
            other => panic!("Expected InvalidUrl, got: {:?}", other),
        }
    }

    #[test]
    fn test_clone_authenticated_bad_repo() {
        let mut scanner = GitScanner::new();
        let result = scanner.clone_repo_authenticated(
            "https://github.com/nonexistent-org-12345/nonexistent-repo-67890",
            None,
            "fake-token",
        );
        assert!(result.is_err());
        // Token must not appear in error messages
        if let Err(GitError::CloneFailed(msg)) = result {
            assert!(!msg.contains("fake-token"), "Token leaked in error: {}", msg);
        }
    }

    #[test]
    fn test_auth_error_variant() {
        let err = GitError::AuthError("token injection failed".to_string());
        assert_eq!(
            err.to_string(),
            "Authentication error: token injection failed"
        );
    }
}
