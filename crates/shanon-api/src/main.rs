//! Shanon Security Oracle — REST API Server
//!
//! Provides HTTP endpoints for:
//! - Querying on-chain risk scores
//! - Triggering new security scans
//! - Viewing assessment details and flags
//! - Analyst dashboard data
//!
//! All Solana data is read live from the chain — no cached/mock data.

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};

mod routes;
pub mod scoreboard;
pub mod badge;
pub mod rate_limiter;
pub mod openapi;

// ─── App State ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    /// Solana RPC client — connects to devnet/mainnet.
    pub rpc_client: Arc<RpcClient>,
    /// Shanon Oracle program ID.
    pub oracle_program_id: Pubkey,
    /// Security scoreboard store
    pub scoreboard: Option<Arc<scoreboard::ScoreboardStore>>,
    /// API key for authenticated endpoints (from environment).
    pub api_key: Option<String>,
}

// ─── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub rpc_url: String,
    pub oracle_program_id: String,
    pub api_key: Option<String>,
    /// Allowed CORS origin(s). If unset or "*", allows any origin (dev mode).
    /// Set to a specific origin for production, e.g. "https://app.shanon.security".
    pub cors_origin: Option<String>,
}

impl ApiConfig {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("SHANON_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("SHANON_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .unwrap_or(8080),
            rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".into()),
            oracle_program_id: std::env::var("SHANON_ORACLE_PROGRAM_ID")
                .unwrap_or_else(|_| shanon_oracle::ID.to_string()),
            api_key: std::env::var("SHANON_API_KEY").ok(),
            cors_origin: std::env::var("SHANON_CORS_ORIGIN").ok(),
        }
    }
}

// ─── Auth Middleware ────────────────────────────────────────────────────────

pub fn authenticate(req: &HttpRequest, state: &AppState) -> Result<(), HttpResponse> {
    // If no API key configured, all requests are allowed (dev mode)
    let required_key = match &state.api_key {
        Some(key) => key,
        None => return Ok(()),
    };

    let provided_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok());

    match provided_key {
        Some(key) if key == required_key => Ok(()),
        _ => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid or missing API key",
            "hint": "Set the X-API-Key header"
        }))),
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // ─── Enterprise Observability: Structured JSON Logging ───
    let is_json = std::env::var("LOG_FORMAT").unwrap_or_default() == "json";
    
    if is_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "shanon_api=info,actix_web=info".into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "shanon_api=info,actix_web=info".into()),
            )
            .init();
    }

    let config = ApiConfig::from_env();

    info!("Shanon Security Oracle API starting");
    info!("RPC URL: {}", config.rpc_url);
    info!("Oracle Program: {}", config.oracle_program_id);
    info!("Binding to {}:{}", config.host, config.port);

    let rpc_client = Arc::new(RpcClient::new(config.rpc_url.clone()));
    let oracle_program_id = match Pubkey::from_str(&config.oracle_program_id) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("ERROR: Invalid oracle program ID '{}': {}", config.oracle_program_id, e);
            std::process::exit(1);
        }
    };

    let state = AppState {
        rpc_client,
        oracle_program_id,
        scoreboard: Some(Arc::new(scoreboard::ScoreboardStore::new())),
        api_key: config.api_key,
    };

    // Rate limiter — configured via SHANON_RATE_LIMIT_RPS and SHANON_RATE_LIMIT_BURST
    let rate_limiter = web::Data::new(rate_limiter::RateLimiterState::from_env());
    info!("Rate limiter: {} req/s, burst {}", rate_limiter.requests_per_second, rate_limiter.burst_size);

    // CORS — configurable via SHANON_CORS_ORIGIN
    let cors_origin = config.cors_origin.clone();
    if cors_origin.is_none() || cors_origin.as_deref() == Some("*") {
        warn!("CORS: allowing any origin (dev mode). Set SHANON_CORS_ORIGIN for production.");
    } else {
        info!("CORS: restricted to {}", cors_origin.as_deref().unwrap_or("*"));
    }

    HttpServer::new(move || {
        let cors = match cors_origin.as_deref() {
            Some(origin) if origin != "*" => {
                Cors::default()
                    .allowed_origin(origin)
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600)
            }
            _ => {
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600)
            }
        };

        App::new()
            .app_data(web::Data::new(state.clone()))
            .app_data(rate_limiter.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            // OpenAPI documentation
            .configure(openapi::configure)
            // API endpoints
            .route("/health", web::get().to(routes::health))
            .route("/api/v1/risk/{program_id}", web::get().to(routes::get_risk_score))
            .route("/api/v1/risk/{program_id}/flags", web::get().to(routes::get_risk_flags))
            .route("/api/v1/programs", web::get().to(routes::list_scored_programs))
            .route("/api/v1/stats", web::get().to(routes::oracle_stats))
            .route("/api/v1/analyst/{wallet}", web::get().to(routes::get_analyst))
            .route("/api/v1/analysts", web::get().to(routes::list_analysts))
            .route("/api/v1/scan", web::post().to(routes::trigger_scan))
            .route("/api/v1/engines", web::get().to(routes::list_engines))
            .route("/api/v1/detectors", web::get().to(routes::list_detectors))
            .route("/api/v1/exploits", web::get().to(routes::list_exploits))
            .route("/api/v1/archive", web::get().to(routes::list_archives))
            .route("/api/v1/guard", web::post().to(routes::guard_scan))
            // Scoreboard
            .route("/api/v1/scoreboard", web::get().to(routes::scoreboard_list))
            .route("/api/v1/scoreboard/{program_id}", web::get().to(routes::scoreboard_detail))
            .route("/api/v1/scoreboard/scan", web::post().to(routes::scoreboard_scan))
            .route("/api/v1/badge/{program_id}", web::get().to(routes::scoreboard_badge))
            // Token Risk
            .route("/api/v1/token/{mint}/risk", web::get().to(routes::token_risk))
            // Transaction Simulation
            .route("/api/v1/simulate", web::post().to(routes::simulate_transaction))
            // Upgrade Authority
            .route("/api/v1/authority/{program_id}", web::get().to(routes::authority_status))
    })
    .bind((config.host, config.port))?
    .run()
    .await
}
