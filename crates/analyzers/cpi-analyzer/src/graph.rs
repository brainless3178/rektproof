//! CPI Dependency Graph — Cross-Program Risk Propagation
//!
//! Maps cross-program invocation dependencies and calculates how risk
//! propagates through the CPI call graph. A compromised callee can
//! affect all of its callers ("blast radius").

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of CPI call detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CPICallType {
    /// Raw invoke() — highest risk, no type safety
    RawInvoke,
    /// invoke_signed() — still risky if callee unvalidated
    InvokeSigned,
    /// Anchor CPI context — safer, includes program validation
    AnchorCPI,
    /// Unknown/detected from transaction logs
    Unknown,
}

/// A node in the CPI dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramNode {
    /// Program ID (base58)
    pub program_id: String,
    /// Human-readable name (if known)
    pub name: Option<String>,
    /// Security score from program-analyzer (0-100), if available
    pub security_score: Option<u8>,
    /// Whether the program is verified
    pub verified: bool,
    /// Whether the program is upgradeable
    pub is_upgradeable: bool,
    /// Number of incoming CPI edges (callers)
    pub in_degree: usize,
    /// Number of outgoing CPI edges (callees)
    pub out_degree: usize,
}

/// An edge representing a CPI call between two programs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPIEdge {
    /// Calling program
    pub caller: String,
    /// Called program
    pub callee: String,
    /// Type of CPI
    pub call_type: CPICallType,
    /// Number of times this call was observed
    pub frequency: u64,
    /// Risk level of this edge (0-100)
    pub edge_risk: u8,
}

/// Risk propagation result for a program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPropagation {
    /// Program being affected
    pub program_id: String,
    /// The program that is the source of risk
    pub risk_source: String,
    /// Propagated risk score
    pub propagated_risk: u8,
    /// Path through which risk propagates
    pub propagation_path: Vec<String>,
    /// Description of the risk
    pub description: String,
}

/// CPI Dependency Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPIDependencyGraph {
    /// Program nodes indexed by program ID
    pub nodes: HashMap<String, ProgramNode>,
    /// CPI call edges
    pub edges: Vec<CPIEdge>,
    /// Root program being analyzed
    pub root_program: String,
    /// Maximum depth explored
    pub depth: u8,
}

impl CPIDependencyGraph {
    /// Create an empty graph rooted at a specific program
    pub fn new(root_program: &str, depth: u8) -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            root_program: root_program.to_string(),
            depth,
        }
    }

    /// Build a graph from source code analysis (offline mode).
    ///
    /// Scans Rust source files for CPI patterns and builds a dependency
    /// graph based on detected `invoke()`, `invoke_signed()`, and Anchor
    /// CPI calls.
    pub fn build_from_source(
        root_program_id: &str,
        source_code: &str,
        program_name: Option<&str>,
    ) -> Self {
        let mut graph = Self::new(root_program_id, 1);

        // Add root node
        graph.nodes.insert(
            root_program_id.to_string(),
            ProgramNode {
                program_id: root_program_id.to_string(),
                name: program_name.map(|s| s.to_string()),
                security_score: None,
                verified: true,
                is_upgradeable: false,
                in_degree: 0,
                out_degree: 0,
            },
        );

        // Detect CPI targets from source patterns
        let cpi_targets = Self::detect_cpi_targets(source_code);

        for (callee_id, call_type) in &cpi_targets {
            // Add callee node
            graph.nodes.entry(callee_id.clone()).or_insert_with(|| ProgramNode {
                program_id: callee_id.clone(),
                name: Self::known_program_name(callee_id),
                security_score: None,
                verified: false,
                is_upgradeable: false,
                in_degree: 0,
                out_degree: 0,
            });

            // Add edge
            let edge_risk = match call_type {
                CPICallType::RawInvoke => 80,
                CPICallType::InvokeSigned => 60,
                CPICallType::AnchorCPI => 30,
                CPICallType::Unknown => 50,
            };

            graph.edges.push(CPIEdge {
                caller: root_program_id.to_string(),
                callee: callee_id.clone(),
                call_type: call_type.clone(),
                frequency: 1,
                edge_risk,
            });
        }

        // Update degrees
        graph.update_degrees();
        graph
    }

    /// Detect CPI targets from source code patterns
    fn detect_cpi_targets(source: &str) -> Vec<(String, CPICallType)> {
        let mut targets = Vec::new();

        // Known program IDs that appear in CPI calls
        let known_programs: &[(&str, &str)] = &[
            ("token::ID", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            ("system_program::ID", "11111111111111111111111111111111"),
            ("spl_token::id()", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            ("associated_token::ID", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
            ("spl_associated_token_account", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
            ("anchor_spl::token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            ("rent::ID", "SysvarRent111111111111111111111111111111111"),
            ("clock::ID", "SysvarC1ock11111111111111111111111111111111"),
        ];

        for (pattern, program_id) in known_programs {
            if source.contains(pattern) {
                // Determine call type
                let call_type = if source.contains("CpiContext::new") || source.contains("anchor_spl") {
                    CPICallType::AnchorCPI
                } else if source.contains("invoke_signed") {
                    CPICallType::InvokeSigned
                } else if source.contains("invoke(") {
                    CPICallType::RawInvoke
                } else {
                    CPICallType::Unknown
                };

                targets.push((program_id.to_string(), call_type));
            }
        }

        // Detect raw invoke calls to unknown programs
        if source.contains("invoke(") || source.contains("invoke_signed(") {
            let has_known = targets.iter().any(|(_, ct)| {
                matches!(ct, CPICallType::RawInvoke | CPICallType::InvokeSigned)
            });

            if !has_known {
                targets.push((
                    "UnknownProgram".to_string(),
                    if source.contains("invoke_signed(") {
                        CPICallType::InvokeSigned
                    } else {
                        CPICallType::RawInvoke
                    },
                ));
            }
        }

        targets
    }

    /// Update in/out degree counts for all nodes
    fn update_degrees(&mut self) {
        // Reset
        for node in self.nodes.values_mut() {
            node.in_degree = 0;
            node.out_degree = 0;
        }
        // Count
        for edge in &self.edges {
            if let Some(caller) = self.nodes.get_mut(&edge.caller) {
                caller.out_degree += 1;
            }
            if let Some(callee) = self.nodes.get_mut(&edge.callee) {
                callee.in_degree += 1;
            }
        }
    }

    /// Calculate risk propagation through the graph
    ///
    /// If a callee is compromised (low security score, upgradeable, unverified),
    /// risk propagates upstream to all callers.
    pub fn propagate_risk(&self) -> Vec<RiskPropagation> {
        let mut propagations = Vec::new();

        for edge in &self.edges {
            let callee = match self.nodes.get(&edge.callee) {
                Some(n) => n,
                None => continue,
            };

            let mut risk_score = edge.edge_risk;

            // Amplify risk for unverified targets
            if !callee.verified {
                risk_score = (risk_score as f64 * 1.3).min(100.0) as u8;
            }

            // Amplify risk for upgradeable targets
            if callee.is_upgradeable {
                risk_score = (risk_score as f64 * 1.2).min(100.0) as u8;
            }

            // Amplify for low security scores
            if let Some(score) = callee.security_score {
                if score < 50 {
                    risk_score = (risk_score as f64 * 1.4).min(100.0) as u8;
                }
            }

            if risk_score > 20 {
                let callee_name = callee.name.clone().unwrap_or_else(|| edge.callee[..8.min(edge.callee.len())].to_string());

                propagations.push(RiskPropagation {
                    program_id: edge.caller.clone(),
                    risk_source: edge.callee.clone(),
                    propagated_risk: risk_score,
                    propagation_path: vec![edge.caller.clone(), edge.callee.clone()],
                    description: format!(
                        "CPI to {} ({}) via {:?} — risk score {}",
                        callee_name,
                        if callee.verified { "verified" } else { "UNVERIFIED" },
                        edge.call_type,
                        risk_score
                    ),
                });
            }
        }

        // Sort by risk (highest first)
        propagations.sort_by(|a, b| b.propagated_risk.cmp(&a.propagated_risk));
        propagations
    }

    /// Export as D3.js-compatible JSON for visualization
    pub fn to_d3_json(&self) -> String {
        #[derive(Serialize)]
        struct D3Graph {
            nodes: Vec<D3Node>,
            links: Vec<D3Link>,
        }

        #[derive(Serialize)]
        struct D3Node {
            id: String,
            name: String,
            security_score: Option<u8>,
            verified: bool,
            group: u8,
        }

        #[derive(Serialize)]
        struct D3Link {
            source: String,
            target: String,
            call_type: String,
            risk: u8,
        }

        let d3 = D3Graph {
            nodes: self
                .nodes
                .values()
                .map(|n| D3Node {
                    id: n.program_id.clone(),
                    name: n.name.clone().unwrap_or_else(|| n.program_id[..8.min(n.program_id.len())].to_string()),
                    security_score: n.security_score,
                    verified: n.verified,
                    group: if n.program_id == self.root_program { 0 } else { 1 },
                })
                .collect(),
            links: self
                .edges
                .iter()
                .map(|e| D3Link {
                    source: e.caller.clone(),
                    target: e.callee.clone(),
                    call_type: format!("{:?}", e.call_type),
                    risk: e.edge_risk,
                })
                .collect(),
        };

        serde_json::to_string_pretty(&d3).unwrap_or_default()
    }

    /// Get summary statistics
    pub fn summary(&self) -> GraphSummary {
        let risky_edges = self.edges.iter().filter(|e| e.edge_risk >= 50).count();
        let unverified = self.nodes.values().filter(|n| !n.verified).count();

        GraphSummary {
            total_programs: self.nodes.len(),
            total_cpi_calls: self.edges.len(),
            risky_calls: risky_edges,
            unverified_dependencies: unverified,
            max_risk: self.edges.iter().map(|e| e.edge_risk).max().unwrap_or(0),
        }
    }

    /// Look up human-readable names for known Solana programs
    fn known_program_name(program_id: &str) -> Option<String> {
        match program_id {
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" => Some("Token Program".into()),
            "11111111111111111111111111111111" => Some("System Program".into()),
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" => Some("Associated Token".into()),
            "SysvarRent111111111111111111111111111111111" => Some("Rent Sysvar".into()),
            "SysvarC1ock11111111111111111111111111111111" => Some("Clock Sysvar".into()),
            "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s" => Some("Metaplex Token Metadata".into()),
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc" => Some("Orca Whirlpool".into()),
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" => Some("Raydium AMM".into()),
            _ => None,
        }
    }
}

/// Summary statistics for a CPI graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub total_programs: usize,
    pub total_cpi_calls: usize,
    pub risky_calls: usize,
    pub unverified_dependencies: usize,
    pub max_risk: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_creation() {
        let graph = CPIDependencyGraph::new("TestProgram111", 2);
        assert_eq!(graph.root_program, "TestProgram111");
        assert_eq!(graph.depth, 2);
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn test_build_from_source_with_anchor() {
        let source = r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token;
            
            pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
                let cpi_ctx = CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.from.to_account_info(),
                        to: ctx.accounts.to.to_account_info(),
                        authority: ctx.accounts.authority.to_account_info(),
                    },
                );
                token::transfer(cpi_ctx, amount)
            }
        "#;

        let graph = CPIDependencyGraph::build_from_source("MyProgram111", source, Some("My Token Program"));
        assert!(graph.nodes.len() >= 2); // root + token program
        assert!(!graph.edges.is_empty());

        // Token program edge should be AnchorCPI
        let token_edge = graph.edges.iter().find(|e| {
            e.callee == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        });
        assert!(token_edge.is_some());
        assert_eq!(token_edge.unwrap().call_type, CPICallType::AnchorCPI);
    }

    #[test]
    fn test_build_from_raw_invoke() {
        let source = r#"
            let ix = Instruction { program_id: *program_id, accounts, data };
            invoke(&ix, &[account.clone()])?;
        "#;

        let graph = CPIDependencyGraph::build_from_source("RawProg111", source, None);
        assert!(!graph.edges.is_empty());
    }

    #[test]
    fn test_risk_propagation() {
        let mut graph = CPIDependencyGraph::new("Root111", 1);

        graph.nodes.insert("Root111".into(), ProgramNode {
            program_id: "Root111".into(),
            name: Some("Root".into()),
            security_score: Some(90),
            verified: true,
            is_upgradeable: false,
            in_degree: 0,
            out_degree: 1,
        });

        graph.nodes.insert("Unverified222".into(), ProgramNode {
            program_id: "Unverified222".into(),
            name: Some("Sketchy".into()),
            security_score: Some(30),
            verified: false,
            is_upgradeable: true,
            in_degree: 1,
            out_degree: 0,
        });

        graph.edges.push(CPIEdge {
            caller: "Root111".into(),
            callee: "Unverified222".into(),
            call_type: CPICallType::RawInvoke,
            frequency: 5,
            edge_risk: 80,
        });

        let risks = graph.propagate_risk();
        assert!(!risks.is_empty());
        // Risk should be amplified for unverified + upgradeable + low score
        assert!(risks[0].propagated_risk > 80);
    }

    #[test]
    fn test_d3_json_output() {
        let source = "use anchor_spl::token; let ctx = CpiContext::new(prog, accs);";
        let graph = CPIDependencyGraph::build_from_source("Prog111", source, Some("Test"));
        let json = graph.to_d3_json();
        assert!(json.contains("nodes"));
        assert!(json.contains("links"));
    }

    #[test]
    fn test_summary() {
        let graph = CPIDependencyGraph::new("Test111", 1);
        let summary = graph.summary();
        assert_eq!(summary.total_programs, 0);
        assert_eq!(summary.total_cpi_calls, 0);
    }

    #[test]
    fn test_known_program_names() {
        assert_eq!(
            CPIDependencyGraph::known_program_name("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            Some("Token Program".into())
        );
        assert_eq!(
            CPIDependencyGraph::known_program_name("11111111111111111111111111111111"),
            Some("System Program".into())
        );
        assert_eq!(
            CPIDependencyGraph::known_program_name("RandomUnknownXXX"),
            None
        );
    }
}
