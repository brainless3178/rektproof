use std::collections::HashMap;
use crate::abstract_domain::{AbstractState, AbstractDomain, AnalysisContext};
use crate::cfg_analyzer::{ControlFlowGraph, BlockId, BasicBlock, StmtKind};

use crate::octagon_domain::{OctagonState, OctagonVerificationResult};

/// STEP 3 — Build the Fixpoint Engine (Isolated & Safe)
/// 
/// A monotone framework solver that propagates abstract states through the CFG.
pub fn analyze(cfg: &ControlFlowGraph, initial_state: &AbstractState) -> HashMap<BlockId, AbstractState> {
    let mut states: HashMap<BlockId, AbstractState> = HashMap::new();
    let thresholds = collect_thresholds(cfg);
    let context = AnalysisContext::new(thresholds);

    // 3.1 Initialize all blocks with default (bottom)
    for block in &cfg.blocks {
        states.insert(block.id, AbstractState::default());
    }

    // Set entry block state
    states.insert(cfg.entry, initial_state.clone());

    let mut iterations = 0;
    loop {
        let mut changed = false;
        iterations += 1;

        for block in &cfg.blocks {
            // 3.3 Join Predecessors
            let mut in_state = join_predecessors(cfg, block.id, &states);
            
            // STEP 9 — Widening for loop convergence
            // If this is a loop header, apply widening after a few iterations
            let current = states.get(&block.id).unwrap();
            let is_loop_header = block.statements.iter().any(|s| s.kind == StmtKind::LoopHeader);
            
            if is_loop_header && iterations > 2 {
                in_state = current.widen(&in_state, &context);
            }

            // 3.5 Transfer Block
            let out_state = transfer_block(block, &in_state);

            // 3.2 Comparison (PartialEq)
            if &out_state != current {
                // 3.6 Debug Logging
                // println!("[Fixpoint] Block {} changed at iteration {}", block.id, iterations);
                states.insert(block.id, out_state);
                changed = true;
            }
        }

        if !changed || iterations > 100 {
            if iterations > 100 {
                eprintln!("[Fixpoint] Warning: Maximum iterations reached for {}", cfg.function_name);
            }
            break;
        }
    }

    states
}

/// Collect constant thresholds from the CFG for guided widening.
fn collect_thresholds(cfg: &ControlFlowGraph) -> Vec<i128> {
    let mut ts = Vec::new();

    for block in &cfg.blocks {
        for stmt in &block.statements {
            if let Some(ref raw_stmt) = stmt.raw {
                match raw_stmt {
                    syn::Stmt::Local(local) => {
                        if let Some((_, expr)) = crate::octagon_domain::extract_assignment(local) {
                            if let Some(c) = crate::octagon_domain::extract_constant(expr) {
                                ts.push(c);
                            }
                        }
                    }
                    syn::Stmt::Expr(expr, _) | syn::Stmt::Semi(expr, _) => {
                        if let Some((_, _, rhs)) = crate::octagon_domain::extract_comparison(expr) {
                            if let Some(c) = crate::octagon_domain::extract_constant(rhs) {
                                ts.push(c);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    ts.sort();
    ts.dedup();
    println!("[Fixpoint] Collected {} thresholds: {:?}", ts.len(), ts);
    ts
}

// ── Shadow Mode Integration (Step 4) ──────────────────────────────────

/// STEP 4.2 — Extract Comparable Results
///
/// Merges all block states into a single OctagonState for global comparison.
pub fn extract_octagon_summary(
    states: &HashMap<BlockId, AbstractState>
) -> OctagonState {
    let mut states_iter = states.values();
    let mut result = match states_iter.next() {
        Some(s) => s.octagon.clone(),
        None => return OctagonState::new(&[]),
    };

    for state in states_iter {
        result = result.join(&state.octagon);
    }

    result
}

/// STEP 4.3 — Compare Old vs New
///
/// Logs differences between the existing structural scan and the new fixpoint logic.
pub fn compare_results(old: &OctagonState, new: &OctagonState, fn_name: &str) {
    if old != new {
        println!("⚠️  [Shadow Mode] Octagon mismatch detected in function: {}", fn_name);
        println!("  OLD: {:?}", old);
        println!("  NEW: {:?}", new);
    } else {
        // println!("✅ [Shadow Mode] Octagon states match for: {}", fn_name);
    }
}

/// 3.3 Join Predecessors Logic
fn join_predecessors(
    cfg: &ControlFlowGraph,
    block_id: BlockId,
    states: &HashMap<BlockId, AbstractState>,
) -> AbstractState {
    let block = &cfg.blocks[block_id];
    let preds = &block.predecessors;

    if preds.is_empty() {
        // Entry block or unreachable
        return AbstractState::default();
    }

    let mut result = states.get(&preds[0]).unwrap().clone();

    for i in 1..preds.len() {
        let pred_state = states.get(&preds[i]).unwrap();
        result = join_states(&result, pred_state);
    }

    result
}

/// 3.4 Join Logic (State-Level)
fn join_states(a: &AbstractState, b: &AbstractState) -> AbstractState {
    a.join(b)
}

/// 3.5 Transfer Block (Semantic Transfer)
fn transfer_block(block: &BasicBlock, state: &AbstractState) -> AbstractState {
    let mut current = state.clone();

    for stmt in &block.statements {
        if let Some(ref raw_stmt) = stmt.raw {
            current.octagon = current.octagon.transfer(raw_stmt);
        }
    }

    current
}
