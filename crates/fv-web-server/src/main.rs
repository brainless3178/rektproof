//! Firedancer Verifier Web Server
//!
//! Enterprise-grade HTTP API for triggering and monitoring security scans.
//!
//! Security measures:
//! - API key authentication via `X-API-Key` header
//! - Path traversal prevention (canonicalization + allowlist)
//! - Restricted CORS (configurable allowed origins)
//! - Cryptographically random scan IDs (UUID v4)
//! - Rate limiting via configurable scan concurrency cap
//! - No internal path leakage in error responses

use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Result as ActixResult, middleware};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

use fv_scanner_core::{Scanner, ScanConfig, ScanProgress};

// ─── Configuration ───────────────────────────────────────────────────────────

/// Server configuration loaded from environment variables.
struct ServerConfig {
    /// API key required for all endpoints. Set via `FV_API_KEY`.
    api_key: String,
    /// Allowed base directories for scan targets. Set via `FV_ALLOWED_PATHS` (comma-separated).
    allowed_base_paths: Vec<PathBuf>,
    /// Allowed CORS origins. Set via `FV_CORS_ORIGINS` (comma-separated).
    /// Defaults to `http://localhost:3000` in development.
    cors_origins: Vec<String>,
    /// Maximum concurrent scans. Set via `FV_MAX_CONCURRENT_SCANS`. Default: 5.
    max_concurrent_scans: usize,
    /// Bind address. Set via `FV_BIND_ADDR`. Default: `127.0.0.1:8080`.
    bind_addr: String,
}

impl ServerConfig {
    fn from_env() -> Self {
        let api_key = std::env::var("FV_API_KEY")
            .expect("FV_API_KEY environment variable must be set");

        let allowed_base_paths: Vec<PathBuf> = std::env::var("FV_ALLOWED_PATHS")
            .unwrap_or_else(|_| "/tmp/scan_targets".to_string())
            .split(',')
            .map(|s| PathBuf::from(s.trim()))
            .collect();

        let cors_origins: Vec<String> = std::env::var("FV_CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let max_concurrent_scans: usize = std::env::var("FV_MAX_CONCURRENT_SCANS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let bind_addr = std::env::var("FV_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string());

        Self {
            api_key,
            allowed_base_paths,
            cors_origins,
            max_concurrent_scans,
            bind_addr,
        }
    }
}

// ─── App State ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    active_scans: Arc<Mutex<HashMap<String, ScanStatus>>>,
    api_key: String,
    allowed_base_paths: Vec<PathBuf>,
    max_concurrent_scans: usize,
}

#[derive(Clone, Serialize)]
struct ScanStatus {
    scan_id: String,
    status: String,
    progress: u8,
    message: String,
}

// ─── Request / Response ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    layers: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct ScanResponse {
    scan_id: String,
    message: String,
    status_url: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Security: Authentication ────────────────────────────────────────────────

/// Validate the API key from the `X-API-Key` header.
fn authenticate(req: &HttpRequest, state: &AppState) -> Result<(), HttpResponse> {
    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok());

    match api_key {
        Some(key) if key == state.api_key => Ok(()),
        Some(_) => Err(HttpResponse::Forbidden().json(ErrorResponse {
            error: "Invalid API key".to_string(),
        })),
        None => Err(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Missing X-API-Key header".to_string(),
        })),
    }
}

// ─── Security: Path Validation ───────────────────────────────────────────────

/// Validate and canonicalize the target path.
///
/// Defenses:
/// 1. Canonicalize the path to resolve `..`, symlinks, etc.
/// 2. Verify the canonical path is under one of the allowed base directories.
/// 3. Verify the path exists and is a directory (not a file like /etc/passwd).
fn validate_target_path(
    target: &str,
    allowed_base_paths: &[PathBuf],
) -> Result<PathBuf, String> {
    let raw_path = PathBuf::from(target);

    // Reject obviously suspicious patterns before touching the filesystem
    if target.contains("..") || target.contains('\0') {
        return Err("Invalid path".to_string());
    }

    // Canonicalize to resolve symlinks and relative components
    let canonical = raw_path
        .canonicalize()
        .map_err(|_| "Target path does not exist".to_string())?;

    // Ensure canonical path is under an allowed base directory
    let is_allowed = allowed_base_paths
        .iter()
        .any(|base| {
            base.canonicalize()
                .map(|cb| canonical.starts_with(&cb))
                .unwrap_or(false)
        });

    if !is_allowed {
        log::warn!(
            "Path traversal attempt blocked: requested={}, canonical={:?}",
            target,
            canonical
        );
        return Err("Target path is not in an allowed directory".to_string());
    }

    // Must be a directory, not a file
    if !canonical.is_dir() {
        return Err("Target path must be a directory".to_string());
    }

    Ok(canonical)
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn start_scan(
    req: HttpRequest,
    body: web::Json<ScanRequest>,
    state: web::Data<AppState>,
) -> ActixResult<HttpResponse> {
    // Auth check
    if let Err(resp) = authenticate(&req, &state) {
        return Ok(resp);
    }

    // Validate target path (prevents path traversal)
    let target_path = match validate_target_path(&body.target, &state.allowed_base_paths) {
        Ok(p) => p,
        Err(msg) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse { error: msg }));
        }
    };

    // Enforce concurrency limit
    {
        let scans = state.active_scans.lock().await;
        let running = scans.values().filter(|s| s.status == "running").count();
        if running >= state.max_concurrent_scans {
            return Ok(HttpResponse::TooManyRequests().json(ErrorResponse {
                error: format!(
                    "Maximum concurrent scans ({}) reached. Try again later.",
                    state.max_concurrent_scans
                ),
            }));
        }
    }

    // Generate cryptographically random scan ID
    let scan_id = format!("scan_{}", Uuid::new_v4());

    let mut config = ScanConfig::default();
    if let Some(layers) = &body.layers {
        config.enabled_layers = layers.clone();
    }

    let status = ScanStatus {
        scan_id: scan_id.clone(),
        status: "running".to_string(),
        progress: 0,
        message: "Scan started".to_string(),
    };

    state.active_scans.lock().await.insert(scan_id.clone(), status);

    let state_clone = state.clone();
    let scan_id_clone = scan_id.clone();

    tokio::spawn(async move {
        let scanner = Scanner::new(config);
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        let state_for_progress = state_clone.clone();
        let scan_id_for_progress = scan_id_clone.clone();
        tokio::spawn(async move {
            while let Some(progress) = rx.recv().await {
                let mut scans = state_for_progress.active_scans.lock().await;
                if let Some(status) = scans.get_mut(&scan_id_for_progress) {
                    match progress {
                        ScanProgress::Started { layer, name } => {
                            status.progress = (layer - 1) * 25;
                            status.message = format!("Running Layer {}: {}", layer, name);
                        }
                        ScanProgress::Completed { layer, .. } => {
                            status.progress = layer * 25;
                            status.message = format!("Layer {} completed", layer);
                        }
                        _ => {}
                    }
                }
            }
        });

        match scanner.scan_with_progress(&target_path, tx).await {
            Ok(_) => {
                let mut scans = state_clone.active_scans.lock().await;
                if let Some(status) = scans.get_mut(&scan_id_clone) {
                    status.status = "completed".to_string();
                    status.progress = 100;
                    status.message = "Scan completed successfully".to_string();
                }
            }
            Err(e) => {
                let mut scans = state_clone.active_scans.lock().await;
                if let Some(status) = scans.get_mut(&scan_id_clone) {
                    status.status = "failed".to_string();
                    // Do not leak internal error details to client
                    status.message = "Scan failed. Check server logs for details.".to_string();
                }
                log::error!("Scan {} failed: {}", scan_id_clone, e);
            }
        }
    });

    Ok(HttpResponse::Ok().json(ScanResponse {
        scan_id: scan_id.clone(),
        message: "Scan started successfully".to_string(),
        status_url: format!("/api/v1/scan/{}", scan_id),
    }))
}

async fn get_scan_status(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> ActixResult<HttpResponse> {
    // Auth check
    if let Err(resp) = authenticate(&req, &state) {
        return Ok(resp);
    }

    let scan_id = path.into_inner();
    let scans = state.active_scans.lock().await;

    if let Some(status) = scans.get(&scan_id) {
        Ok(HttpResponse::Ok().json(status))
    } else {
        Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "Scan not found".to_string(),
        }))
    }
}

/// Health check endpoint (no auth required).
async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "fv-web-server",
    })))
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = ServerConfig::from_env();
    let bind_addr = config.bind_addr.clone();
    let cors_origins = config.cors_origins.clone();

    let app_state = AppState {
        active_scans: Arc::new(Mutex::new(HashMap::new())),
        api_key: config.api_key,
        allowed_base_paths: config.allowed_base_paths,
        max_concurrent_scans: config.max_concurrent_scans,
    };

    log::info!("Starting FV web server at {}", bind_addr);
    log::info!("Allowed scan paths: {:?}", app_state.allowed_base_paths);
    log::info!("CORS origins: {:?}", cors_origins);
    log::info!("Max concurrent scans: {}", app_state.max_concurrent_scans);

    HttpServer::new(move || {
        // Build restricted CORS policy
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::HeaderName::from_static("x-api-key"),
            ])
            .max_age(3600);

        for origin in &cors_origins {
            cors = cors.allowed_origin(origin);
        }

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(health))
            .service(
                web::scope("/api/v1")
                    .route("/scan", web::post().to(start_scan))
                    .route("/scan/{scan_id}", web::get().to(get_scan_status))
            )
    })
    .bind(&bind_addr)?
    .run()
    .await
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_blocked() {
        let allowed = vec![PathBuf::from("/tmp/scan_targets")];

        // Path traversal attempts
        assert!(validate_target_path("../../etc/passwd", &allowed).is_err());
        assert!(validate_target_path("/etc/passwd", &allowed).is_err());
        assert!(validate_target_path("/tmp/../etc/shadow", &allowed).is_err());
    }

    #[test]
    fn test_null_byte_injection_blocked() {
        let allowed = vec![PathBuf::from("/tmp/scan_targets")];
        assert!(validate_target_path("/tmp/scan_targets/foo\0bar", &allowed).is_err());
    }

    #[test]
    fn test_scan_id_is_uuid() {
        let id = format!("scan_{}", Uuid::new_v4());
        assert!(id.starts_with("scan_"));
        assert!(id.len() > 20); // UUIDs are 36 chars
    }

    #[test]
    fn test_valid_path_accepted() {
        // Only works if /tmp exists (it always does on Linux)
        let allowed = vec![PathBuf::from("/tmp")];
        let result = validate_target_path("/tmp", &allowed);
        assert!(result.is_ok());
    }
}
