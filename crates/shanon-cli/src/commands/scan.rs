//! `scan-repo` command — clone a Git repository and run the full scan pipeline.

use colored::*;

/// Clone a remote Git repository and run the full scan pipeline on it.
pub async fn cmd_scan_repo(url: &str, branch: Option<&str>, format: &str, min_severity: &str) {
    eprintln!("\n  {}  Cloning repository: {}", "📦".to_string(), url);
    let mut scanner = git_scanner::GitScanner::new();
    let repo_path = match scanner.clone_repo(url, branch) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  {} Failed to clone: {:?}", "X".red(), e);
            std::process::exit(1);
        }
    };
    let path_str = repo_path.to_string_lossy().to_string();
    eprintln!("  {}  Cloned to: {}", "ok".green(), path_str);

    // Run the standard scan on the cloned repo (no AI/fix/poc/simulate by default)
    crate::cmd_scan(&path_str, format, min_severity, false, None, "moonshotai/kimi-k2.5", false, false, false, false, false, false).await;

    // Generate deployment package summary
    let package = integration_orchestrator::IntegrationOrchestrator::generate_deployment_package_for_id(url);
    if format == "json" {
        eprintln!("{}", serde_json::to_string_pretty(&package).unwrap_or_default());
    } else {
        eprintln!("\n  {}  Deployment Package Generated", "📋".to_string());
        eprintln!("  ├─ Secure Template:  {} bytes", package.secure_code_template.len());
    }

    // Cleanup cloned repo
    scanner.cleanup();
    eprintln!("  {}  Temporary clone cleaned up", "🧹".to_string());
}
