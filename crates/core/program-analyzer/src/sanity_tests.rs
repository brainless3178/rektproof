
#[cfg(test)]
mod tests {
    use crate::octagon_domain::{OctagonState, INF};
    use crate::cfg_analyzer::{ControlFlowGraph, StmtKind};
    use crate::fixpoint_engine::{analyze, extract_octagon_summary};
    use crate::abstract_domain::AbstractState;
    use syn::{parse_quote, Stmt};

    fn run_test(stmts: Vec<Stmt>) -> OctagonState {
        let cfg = ControlFlowGraph::build("test_func", &stmts);
        let initial_state = AbstractState::default();
        let states = analyze(&cfg, &initial_state);
        extract_octagon_summary(&states)
    }

    #[test]
    fn test_1_reassignment() {
        println!("--- Running Test 1: Reassignment ---");
        let stmts: Vec<Stmt> = vec![
            parse_quote! { let x = 5; },
            parse_quote! { let x = 10; },
        ];
        let result = run_test(stmts);
        
        println!("Test 1 Final State: {:?}", result);
        let val = result.upper_bound("x").expect("x should have a bound");
        assert_eq!(val, 10, "x should be 10, got {}", val);
        let lo = result.lower_bound("x").expect("x should have a lower bound");
        assert_eq!(lo, 10, "x should be 10, got {}", lo);
    }

    #[test]
    fn test_2_branch_join() {
        println!("--- Running Test 2: Branch Join ---");
        // fn test(cond: bool) { 
        //     let x = 5; 
        //     if cond { 
        //         let x = 10; 
        //     } 
        // } 
        // Note: Our CFG builder is simplified. 
        // We'll simulate a branch by manually constructing a CFG or using a snippet that triggers StmtKind::Branch.
        let stmts: Vec<Stmt> = vec![
            parse_quote! { let x = 5; },
            parse_quote! { if cond { x = 10; } }, // Simplified assignment
        ];
        let result = run_test(stmts);
        
        println!("Test 2 Final State: {:?}", result);
        let hi = result.upper_bound("x").expect("x should have upper bound");
        let lo = result.lower_bound("x").expect("x should have lower bound");
        // Expected: x ∈ [5, 10]
        assert!(lo <= 5 && hi >= 10, "x should be in [5, 10], got [{}, {}]", lo, hi);
    }

    #[test]
    fn test_3_loop_stability() {
        println!("--- Running Test 3: Loop Stability ---");
        let stmts: Vec<Stmt> = vec![
            parse_quote! { let mut x = 0; },
            parse_quote! { while x < 10 { x = x + 1; } },
        ];
        let result = run_test(stmts);
        
        println!("Test 3 Final State: {:?}", result);
        let hi = result.upper_bound("x").expect("x should have upper bound");
        // Expected: x ≤ 10 (or something finite)
        assert!(hi >= 10 && hi < 1000, "x should converge to something reasonable, got {}", hi);
    }

    #[test]
    fn test_4_guard_precision() {
        let stmts: Vec<Stmt> = vec![
            parse_quote! { let x = 5; },
            parse_quote! { if x < 10 { let y = 1; } },
        ];
        // We need to inspect the state *inside* the branch.
        // Our current run_test returns a summary (join of all blocks).
        // For Test 4, we need to look at the block state after the guard.
        let cfg = ControlFlowGraph::build("test_guard", &stmts);
        let initial_state = AbstractState::default();
        let states = analyze(&cfg, &initial_state);
        
        // Block 0: let x = 5
        // Block 1: if x < 10
        // Block 2: let y = 1 (inside branch)
        let inside_state = &states.get(&2).expect("Block 2 should exist").octagon;
        println!("Test 4 Inside State: {:?}", inside_state);
        
        let val_x = inside_state.upper_bound("x").unwrap();
        let lo_x = inside_state.lower_bound("x").unwrap();
        assert_eq!(val_x, 5, "x should remain 5 inside branch, got {}", val_x);
        assert_eq!(lo_x, 5, "x should remain 5 inside branch, got {}", lo_x);
    }
}
