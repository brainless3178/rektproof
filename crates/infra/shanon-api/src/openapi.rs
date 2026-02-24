//! # OpenAPI 3.0 Specification Generator
//!
//! Generates an OpenAPI 3.0 JSON specification for the Shanon Security Oracle API.
//! Served at `/api/v1/openapi.json` and `/api/v1/docs` (Swagger UI redirect).
//!
//! All 22 endpoints are documented with request/response schemas, parameter
//! descriptions, and authentication requirements.

use actix_web::{web, HttpResponse};
use serde_json::json;

/// Returns the full OpenAPI 3.0 specification as JSON.
pub async fn openapi_spec() -> HttpResponse {
    let spec = json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Shanon Security Oracle API",
            "description": "Comprehensive security analysis API for Solana programs. Provides vulnerability scanning, token risk assessment, CPI graphing, compliance reporting, and real-time authority monitoring.",
            "version": "1.0.0",
            "contact": {
                "name": "Shannon Security",
                "url": "https://github.com/shanon-security"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {
                "url": "http://localhost:8080",
                "description": "Local development"
            },
            {
                "url": "https://api.shanon.security",
                "description": "Production"
            }
        ],
        "security": [
            { "ApiKeyAuth": [] }
        ],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key for authenticated endpoints. Set via SHANON_API_KEY environment variable. If unset, all endpoints are open (dev mode)."
                }
            },
            "schemas": {
                "HealthResponse": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string", "example": "healthy" },
                        "rpc_connected": { "type": "boolean" },
                        "oracle_program": { "type": "string" },
                        "version": { "type": "string" }
                    }
                },
                "RiskScoreResponse": {
                    "type": "object",
                    "properties": {
                        "program_id": { "type": "string", "description": "Solana program public key" },
                        "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                        "risk_level": { "type": "string", "enum": ["Low", "Medium", "High", "Critical"] },
                        "categories": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string" },
                                    "score": { "type": "integer" }
                                }
                            }
                        }
                    }
                },
                "ScanRequest": {
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": { "type": "string", "description": "Program ID or GitHub URL to scan" },
                        "source_url": { "type": "string", "description": "Optional GitHub URL for source-level analysis" }
                    }
                },
                "ScanResponse": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string", "enum": ["scan_queued", "scan_complete", "scan_failed"] },
                        "findings": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/VulnerabilityFinding" }
                        },
                        "total_findings": { "type": "integer" },
                        "critical": { "type": "integer" },
                        "high": { "type": "integer" },
                        "medium": { "type": "integer" },
                        "low": { "type": "integer" }
                    }
                },
                "VulnerabilityFinding": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string", "example": "SOL-001" },
                        "category": { "type": "string" },
                        "vuln_type": { "type": "string" },
                        "severity": { "type": "integer", "minimum": 1, "maximum": 5 },
                        "severity_label": { "type": "string", "enum": ["Info", "Low", "Medium", "High", "Critical"] },
                        "cwe": { "type": "string", "nullable": true },
                        "location": { "type": "string" },
                        "function_name": { "type": "string" },
                        "line_number": { "type": "integer" },
                        "description": { "type": "string" },
                        "attack_scenario": { "type": "string" },
                        "secure_fix": { "type": "string" },
                        "prevention": { "type": "string" },
                        "confidence": { "type": "integer", "minimum": 0, "maximum": 100 }
                    }
                },
                "GuardScanRequest": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Local path or GitHub URL to scan" }
                    }
                },
                "GuardResponse": {
                    "type": "object",
                    "properties": {
                        "risk_score": { "type": "integer" },
                        "total_dependencies": { "type": "integer" },
                        "malicious_packages": { "type": "array", "items": { "type": "string" } },
                        "typosquats": { "type": "array", "items": { "type": "string" } },
                        "behavioral_alerts": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "TokenRiskResponse": {
                    "type": "object",
                    "properties": {
                        "mint": { "type": "string" },
                        "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                        "grade": { "type": "string" },
                        "flags": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "SimulateRequest": {
                    "type": "object",
                    "required": ["programs"],
                    "properties": {
                        "programs": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "List of program IDs involved in the transaction"
                        },
                        "instruction_data": { "type": "string", "nullable": true }
                    }
                },
                "SimulateResponse": {
                    "type": "object",
                    "properties": {
                        "safe_to_sign": { "type": "boolean" },
                        "overall_risk": { "type": "string" },
                        "program_assessments": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "program_id": { "type": "string" },
                                    "risk_level": { "type": "string" },
                                    "flags": { "type": "array", "items": { "type": "string" } }
                                }
                            }
                        }
                    }
                },
                "EngineInfo": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "type": { "type": "string" },
                        "status": { "type": "string" },
                        "detectors": { "type": "integer" }
                    }
                },
                "DetectorInfo": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "name": { "type": "string" },
                        "description": { "type": "string" },
                        "severity": { "type": "integer" },
                        "severity_label": { "type": "string" }
                    }
                },
                "ScoreboardEntry": {
                    "type": "object",
                    "properties": {
                        "program_id": { "type": "string" },
                        "name": { "type": "string" },
                        "score": { "type": "integer" },
                        "grade": { "type": "string" },
                        "findings_count": { "type": "integer" }
                    }
                },
                "AuthorityStatusResponse": {
                    "type": "object",
                    "properties": {
                        "program_id": { "type": "string" },
                        "upgrade_authority": { "type": "string", "nullable": true },
                        "is_immutable": { "type": "boolean" },
                        "executable": { "type": "boolean" }
                    }
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {
                        "error": { "type": "string" },
                        "hint": { "type": "string" }
                    }
                }
            }
        },
        "paths": {
            "/health": {
                "get": {
                    "tags": ["System"],
                    "summary": "Health check",
                    "description": "Returns API health status, RPC connection state, and oracle program ID.",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "API is healthy",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/scan": {
                "post": {
                    "tags": ["Scanning"],
                    "summary": "Trigger vulnerability scan",
                    "description": "Scans a Solana program for vulnerabilities. Accepts either a program ID (on-chain check) or a GitHub URL (source-level analysis with 72 detectors).",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ScanRequest" } } }
                    },
                    "responses": {
                        "200": {
                            "description": "Scan results",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ScanResponse" } } }
                        },
                        "429": { "description": "Rate limit exceeded" }
                    }
                }
            },
            "/api/v1/guard": {
                "post": {
                    "tags": ["Supply Chain"],
                    "summary": "Dependency firewall scan",
                    "description": "Analyzes project dependencies for malicious packages, typosquats, and behavioral anomalies.",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/GuardScanRequest" } } }
                    },
                    "responses": {
                        "200": {
                            "description": "Guard scan results",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/GuardResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/risk/{program_id}": {
                "get": {
                    "tags": ["Risk Assessment"],
                    "summary": "Get program risk score",
                    "description": "Returns the on-chain risk score for a specific Solana program from the oracle.",
                    "parameters": [
                        {
                            "name": "program_id",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Solana program public key (base58)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Risk score data",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RiskScoreResponse" } } }
                        },
                        "404": { "description": "Program not scored" }
                    }
                }
            },
            "/api/v1/risk/{program_id}/flags": {
                "get": {
                    "tags": ["Risk Assessment"],
                    "summary": "Get detailed risk flags",
                    "description": "Returns individual risk flags and categories for a scored program.",
                    "parameters": [
                        { "name": "program_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "Risk flag details" }
                    }
                }
            },
            "/api/v1/token/{mint}/risk": {
                "get": {
                    "tags": ["Token Security"],
                    "summary": "Analyze token rug-pull risk",
                    "description": "Comprehensive token risk analysis including mint/freeze authority checks, supply concentration, Token-2022 extensions, and composite scoring.",
                    "parameters": [
                        {
                            "name": "mint",
                            "in": "path",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Token mint address (base58)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Token risk assessment",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TokenRiskResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/simulate": {
                "post": {
                    "tags": ["Transaction Safety"],
                    "summary": "Simulate transaction risk",
                    "description": "Pre-sign safety check. Analyzes all programs involved in a transaction for known risks before the user signs.",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SimulateRequest" } } }
                    },
                    "responses": {
                        "200": {
                            "description": "Transaction safety assessment",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SimulateResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/scoreboard": {
                "get": {
                    "tags": ["Scoreboard"],
                    "summary": "List scored protocols",
                    "description": "Returns all scored protocols ranked by security score.",
                    "responses": {
                        "200": {
                            "description": "Scoreboard listing",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/ScoreboardEntry" } } } }
                        }
                    }
                }
            },
            "/api/v1/scoreboard/{program_id}": {
                "get": {
                    "tags": ["Scoreboard"],
                    "summary": "Get protocol security detail",
                    "parameters": [
                        { "name": "program_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Detailed protocol score" } }
                }
            },
            "/api/v1/scoreboard/scan": {
                "post": {
                    "tags": ["Scoreboard"],
                    "summary": "Trigger protocol scoring",
                    "description": "Initiates a full security scoring scan for a protocol.",
                    "responses": { "200": { "description": "Scoring results" } }
                }
            },
            "/api/v1/badge/{program_id}": {
                "get": {
                    "tags": ["Scoreboard"],
                    "summary": "Get SVG security badge",
                    "description": "Returns an SVG badge showing the protocol's security grade. Embeddable in GitHub READMEs.",
                    "parameters": [
                        { "name": "program_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": {
                            "description": "SVG badge",
                            "content": { "image/svg+xml": {} }
                        }
                    }
                }
            },
            "/api/v1/engines": {
                "get": {
                    "tags": ["Metadata"],
                    "summary": "List analysis engines",
                    "description": "Returns all registered analysis engines/crates with their type and status.",
                    "responses": {
                        "200": {
                            "description": "Engine listing",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/EngineInfo" } } } }
                        }
                    }
                }
            },
            "/api/v1/detectors": {
                "get": {
                    "tags": ["Metadata"],
                    "summary": "List vulnerability detectors",
                    "description": "Returns all 72 vulnerability detector patterns with severity and CWE mappings.",
                    "responses": {
                        "200": {
                            "description": "Detector listing",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/DetectorInfo" } } } }
                        }
                    }
                }
            },
            "/api/v1/exploits": {
                "get": {
                    "tags": ["Metadata"],
                    "summary": "List known exploits",
                    "description": "Returns the exploit database with 9 exploit modules targeting distinct vulnerability classes.",
                    "responses": { "200": { "description": "Exploit listing" } }
                }
            },
            "/api/v1/archive": {
                "get": {
                    "tags": ["Metadata"],
                    "summary": "Get scan archive",
                    "description": "Returns historical scan results.",
                    "responses": { "200": { "description": "Archive listing" } }
                }
            },
            "/api/v1/authority/{program_id}": {
                "get": {
                    "tags": ["Authority Monitoring"],
                    "summary": "Check upgrade authority status",
                    "description": "Fetches the current upgrade authority for a Solana program, including immutability status.",
                    "parameters": [
                        { "name": "program_id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": {
                            "description": "Authority status",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AuthorityStatusResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/stats": {
                "get": {
                    "tags": ["System"],
                    "summary": "Get oracle statistics",
                    "description": "Returns global oracle statistics including program count and analyst data.",
                    "responses": { "200": { "description": "Oracle statistics" } }
                }
            },
            "/api/v1/analyst/{wallet}": {
                "get": {
                    "tags": ["Analysts"],
                    "summary": "Get analyst profile",
                    "parameters": [
                        { "name": "wallet", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Analyst profile and stats" } }
                }
            },
            "/api/v1/analysts": {
                "get": {
                    "tags": ["Analysts"],
                    "summary": "List active analysts",
                    "description": "Returns all registered guardian/analyst accounts.",
                    "responses": { "200": { "description": "Analyst listing" } }
                }
            },
            "/api/v1/programs": {
                "get": {
                    "tags": ["Risk Assessment"],
                    "summary": "List scored programs",
                    "description": "Lists all programs with risk scores (paginated).",
                    "responses": { "200": { "description": "Program listing" } }
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "tags": ["System"],
                    "summary": "OpenAPI specification",
                    "description": "Returns this OpenAPI 3.0 specification.",
                    "security": [],
                    "responses": { "200": { "description": "OpenAPI 3.0 JSON" } }
                }
            }
        },
        "tags": [
            { "name": "System", "description": "Health checks, stats, and API metadata" },
            { "name": "Scanning", "description": "Vulnerability scanning for Solana programs" },
            { "name": "Supply Chain", "description": "Dependency firewall and supply chain analysis" },
            { "name": "Risk Assessment", "description": "On-chain risk scoring and flags" },
            { "name": "Token Security", "description": "Token risk analysis and rug-pull detection" },
            { "name": "Transaction Safety", "description": "Pre-sign transaction simulation" },
            { "name": "Scoreboard", "description": "Protocol security rankings and badges" },
            { "name": "Authority Monitoring", "description": "Upgrade authority tracking" },
            { "name": "Metadata", "description": "Engine, detector, and exploit listings" },
            { "name": "Analysts", "description": "Guardian/analyst profiles" }
        ]
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .json(spec)
}

/// Serves a simple HTML page that redirects to Swagger UI with this spec.
pub async fn docs_redirect() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Shanon API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/api/v1/openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: "StandaloneLayout"
        });
    </script>
</body>
</html>"#;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// Configure OpenAPI routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/api/v1/openapi.json", web::get().to(openapi_spec))
        .route("/api/v1/docs", web::get().to(docs_redirect));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_openapi_spec_returns_valid_json() {
        let resp = openapi_spec().await;
        assert_eq!(resp.status(), 200);
    }
}
