# Production Upgrade Plan — Making Every Claim Real

Based on the deep audit findings, this plan addresses every issue to make the project
genuinely production-grade with real mathematical proofs and no false claims.

## Priority 1: Abstract Interpreter — Wire Widening to Real Loops ✅ DONE

**Problem:** Widening/narrowing operators exist but are never applied at loop heads.
Fixed-point iteration doesn't actually run. Expression evaluation is string-based.

**Completed:**
1. ✅ Added AST-based expression evaluation using `syn::Expr` (handles `Binary`, `Lit`, `Path`, `MethodCall`, `Paren`, `Field`, `Unary`, `Cast`)
2. ✅ Detect loops (`while`, `for`, `loop`) in the AST via `interpret_expr_stmt`
3. ✅ Apply widening at loop heads with `MAX_WIDENING_ITERS=20` bound
4. ✅ Apply narrowing pass after convergence via `narrow_state()`
5. ✅ Added recursion depth guard (`MAX_INTERP_DEPTH=10`) to prevent stack overflow
6. ✅ 7 new tests: AST eval, loop widening terminates, checked arithmetic safe, branch joining, narrowing, div-by-zero AST

## Priority 2: Interprocedural Taint Analysis ✅ DONE

**Problem:** All analysis is intraprocedural (single function). No cross-function tracking.

**Completed:**
1. ✅ Build call graph from AST (caller → callee edges with argument extraction)
2. ✅ Function taint summaries: param→return and param→sink tracking
3. ✅ Cross-function taint propagation via summary application at call sites (Phase 3b)
4. ✅ 3 new tests: call graph construction, param tracking, interprocedural propagation

## Priority 3: Split main.rs into Modules — DEFERRED

**Problem:** 1,740-line god file handles all commands.

**Status:** Not critical for correctness. Each `cmd_*` function is self-contained.
Can be addressed in a future refactoring pass.

## Priority 4: AST-Based Expression Evaluation ✅ DONE (merged with Priority 1)

**Completed:** `evaluate_expr_ast()` walks `syn::Expr` variants directly. The old
string-based `evaluate_abstract_expr()` is retained as fallback for macro-generated code
but no longer calls `syn::parse_str` to avoid mutual recursion.

## Priority 5: Source → Z3 Pipeline ✅ DONE

**Problem:** Z3 constraints are manually constructed, not derived from source.

**Completed:**
1. ✅ New `ast_to_z3` module that walks `syn::Expr` and generates Z3 BV64 constraints
2. ✅ Wired into scanning pipeline as Phase 5b
3. ✅ Handles: addition overflow, subtraction underflow, multiplication overflow, division-by-zero, shift overflow
4. ✅ Skips checked/saturating arithmetic (safe by construction)
5. ✅ Returns concrete counterexamples for violations (SAT) or proves safety (UNSAT)
6. ✅ 5 new tests: property extraction, overflow detection, division-by-zero, checked-safe, multiplication

## Priority 6: Honest Naming ✅ DONE

**Completed:**
1. ✅ Removed "ML-inspired" from L3X output → "heuristic reasoning"
2. ✅ README rewritten with "6 analysis techniques, 20 scanning phases"
3. ✅ Added "Honest Capabilities" section (What Works ✅ / Experimental ⚠️ / Missing ❌)
4. ✅ Removed unverifiable precision claims

## Priority 7: CI/CD ✅ DONE

**Completed:**
1. ✅ Added `.github/workflows/ci.yml` with check, test (Z3 installed), clippy, fmt, security audit
2. ✅ Added CI badge to README

## Priority 8: False-Negative Test Suite — TODO

**Fix:**
1. For each SOL-XXX, write a test case with known-vulnerable code
2. Write evasion variants that should NOT be detected (honest blind spots)
3. Document precision/recall per detector

---

## Test Results Summary

| Suite | Count | Status |
|-------|-------|--------|
| Unit tests (lib) | 132 | ✅ All pass |
| Integration tests | 6 | ✅ All pass |
| Property tests | 11 | ✅ All pass |
| **Total** | **149+** | **✅ All pass** |

## New Code Added

| File | Purpose | Lines |
|------|---------|-------|
| `ast_to_z3.rs` | Z3 BV64 constraint generator from `syn::Expr` AST | ~580 |
| `ci.yml` | GitHub Actions CI pipeline | ~70 |
| `README.md` | Honest, accurate README | ~240 |
| `abstract_interp.rs` | Loop widening, AST eval, depth guard (modifications) | ~200 new |
| `taint_lattice.rs` | Call graph, function summaries, IP propagation | ~350 new |
