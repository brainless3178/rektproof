//! # AST-Based Vulnerability Checks
//!
//! Replaces string-matching detection with `syn`-based AST analysis.
//! Each function receives the same `&str` code that the pattern scanner
//! passes (normalized `quote!` output), parses it with `syn`, and walks
//! the AST to determine if the vulnerability is genuinely present.
//!
//! This eliminates false positives caused by string patterns matching
//! comments, field names, or unrelated code.
//!
//! ## Interprocedural Authorization Detection
//!
//! Native Solana programs (non-Anchor) enforce authorization via function calls
//! rather than type-level constraints. For example:
//! - `get_governance_data(program_id, account_info)?` validates ownership
//! - `assert_can_execute_transaction(...)` gates state transitions
//! - `find_program_address(seeds, program_id)` validates PDA derivation
//!
//! The `has_interprocedural_auth` function scans the same code block for these
//! patterns, allowing checkers to suppress false positives when authorization
//! is handled interprocedurally.

use syn::visit::Visit;
use syn::{
    BinOp, Expr, ExprBinary, ExprCall, ExprField, ExprMethodCall,
    Field, Fields, Item, ItemFn, ItemStruct, Type, TypePath,
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Interprocedural Authorization Detection
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code contains evidence of interprocedural authorization.
///
/// This detects authorization patterns common in native Solana programs where
/// access control is enforced via function calls rather than type-level
/// annotations (Anchor's Signer<>, has_one, constraint).
///
/// Recognized patterns:
/// 1. **assert_* calls with ?** — `assert_can_execute(...)` / `assert_signer(...)`
/// 2. **get_*_data(program_id, ...)** — ownership-validating deserializers
/// 3. **find_program_address / create_program_address** — PDA seed validation
/// 4. **invoke_signed with PDA seeds** — PDA signer IS the authorization
/// 5. **is_signer field access** — direct signer checks in function body
pub fn has_interprocedural_auth(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut detector = InterproceduralAuthDetector::default();
    detector.visit_file(&parsed);

    detector.has_auth
}

#[derive(Default)]
struct InterproceduralAuthDetector {
    has_auth: bool,
}

impl<'ast> Visit<'ast> for InterproceduralAuthDetector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let call_str = quote::quote!(#node.func).to_string();
        let call_lower = call_str.to_lowercase();

        // Pattern 1: assert_* validation functions (assert_can_execute, assert_signer, etc.)
        if call_lower.starts_with("assert_") || call_lower.starts_with("assert ::") {
            self.has_auth = true;
        }

        // Pattern 2: get_*_data(program_id, ...) — ownership-validating deserializer
        // These functions verify account_info.owner == program_id before deserializing
        if (call_lower.starts_with("get_") && call_lower.contains("_data"))
            || call_lower.starts_with("get_account_data")
        {
            // Only count as auth if program_id is passed as first arg
            if let Some(first_arg) = node.args.first() {
                let arg_str = quote::quote!(#first_arg).to_string();
                if arg_str.contains("program_id") {
                    self.has_auth = true;
                }
            }
        }

        // Pattern 3: PDA derivation — find_program_address / create_program_address
        if call_str.contains("find_program_address")
            || call_str.contains("create_program_address")
        {
            self.has_auth = true;
        }

        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        let method_lower = method.to_lowercase();

        // Pattern 1: .assert_*() method calls
        if method_lower.starts_with("assert_") {
            self.has_auth = true;
        }

        // Pattern 4: invoke_signed — the PDA signer IS the authorization
        if method == "invoke_signed" {
            self.has_auth = true;
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        // Pattern 5: .is_signer access
        if let syn::Member::Named(ident) = &node.member {
            if ident == "is_signer" {
                self.has_auth = true;
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let mac_name = node.mac.path.segments.last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        // msg! is logging, not auth. But require!, ensure!, assert! are auth.
        if mac_name == "require" || mac_name == "require_keys_eq"
            || mac_name == "require_eq" || mac_name == "ensure"
            || mac_name == "assert" || mac_name == "access_control"
        {
            self.has_auth = true;
        }
        syn::visit::visit_expr_macro(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-001: Missing Signer Check — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code has a genuine missing signer vulnerability.
///
/// The AST check verifies:
/// 1. There is a struct with `AccountInfo<'info>` fields named authority/admin/owner
/// 2. Those fields are NOT wrapped in `Signer<'info>` type
/// 3. There is no `#[account(signer)]` attribute on those fields
/// 4. The function body does NOT contain `is_signer` checks on those specific fields
/// 5. There is no `has_one` or `constraint` that validates the authority
pub fn ast_has_missing_signer(code: &str) -> bool {
    // Parse the combined struct+handler code
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false, // Can't parse → can't confirm vuln
    };

    let mut checker = SignerChecker::default();
    checker.visit_file(&parsed);

    // A real missing signer means: there's an authority-like AccountInfo field
    // WITHOUT any signer enforcement in the struct OR the function body
    checker.has_unprotected_authority && !checker.has_signer_enforcement
}

#[derive(Default)]
struct SignerChecker {
    /// True if we found a field like `pub authority: AccountInfo<'info>`
    has_unprotected_authority: bool,
    /// True if we found signer enforcement (Signer<>, is_signer, has_one, constraint, seeds)
    has_signer_enforcement: bool,
    /// Names of authority-like fields that are raw AccountInfo
    authority_fields: Vec<String>,
    /// We're currently inside an accounts struct
    _in_accounts_struct: bool,
}

impl<'ast> Visit<'ast> for SignerChecker {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        // Check ALL structs for authority-like AccountInfo fields.
        // In the vuln_db flow, the accounts struct prepended may or may not
        // have #[derive(Accounts)]. We also want to catch native programs.
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                self.check_account_field(field);
            }
        }

        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        // Check for `.is_signer` access on any of our authority fields
        if let syn::Member::Named(ident) = &node.member {
            if ident == "is_signer" {
                self.has_signer_enforcement = true;
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        // require_keys_eq!, key() comparisons are signer enforcement patterns
        if method == "key" || method == "require_keys_eq" {
            self.has_signer_enforcement = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let mac_name = node.mac.path.segments.last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if mac_name == "require" || mac_name == "require_keys_eq" || mac_name == "access_control" {
            self.has_signer_enforcement = true;
        }
        syn::visit::visit_expr_macro(self, node);
    }
}

impl SignerChecker {
    fn check_account_field(&mut self, field: &Field) {
        let field_name = field.ident.as_ref()
            .map(|i| i.to_string())
            .unwrap_or_default();

        let is_authority_name = matches!(
            field_name.as_str(),
            "authority" | "admin" | "owner" | "payer" | "signer" | "creator"
        ) || field_name.contains("authority")
          || field_name.contains("admin");

        if !is_authority_name {
            return;
        }

        // Get the type name via the last path segment
        let type_name = Self::extract_type_name(&field.ty);

        // Check for Signer<> type
        if type_name == "Signer" {
            self.has_signer_enforcement = true;
            return;
        }

        // Check for #[account(signer)] or #[account(has_one = ...)]  or seeds = ...
        let has_signer_attr = field.attrs.iter().any(|attr| {
            let s = quote::quote!(#attr).to_string();
            s.contains("signer") || s.contains("has_one") || s.contains("constraint")
                || s.contains("seeds")
        });

        if has_signer_attr {
            self.has_signer_enforcement = true;
            return;
        }

        // If it's raw AccountInfo or UncheckedAccount and named like authority → flag it
        if type_name == "AccountInfo" || type_name == "UncheckedAccount" {
            self.has_unprotected_authority = true;
            self.authority_fields.push(field_name);
        }
    }

    /// Extract the outermost type name from a Type (e.g., "AccountInfo" from AccountInfo<'info>)
    fn extract_type_name(ty: &Type) -> String {
        match ty {
            Type::Path(TypePath { path, .. }) => {
                path.segments.last()
                    .map(|seg| seg.ident.to_string())
                    .unwrap_or_default()
            }
            _ => {
                // Fallback: use quote! and normalize
                let s = quote::quote!(#ty).to_string();
                s.split(|c: char| c == '<' || c == ' ')
                    .next()
                    .unwrap_or("")
                    .to_string()
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-002: Integer Overflow — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code has unchecked arithmetic in a financial context.
///
/// The AST check:
/// 1. Finds binary +, -, * expressions
/// 2. Checks if they're NOT inside a `.checked_add()` / `.saturating_sub()` call
/// 3. Requires the arithmetic to involve variables (not just constants)
/// 4. Checks for financial context (amount, balance, etc.) via variable names
pub fn ast_has_integer_overflow(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = OverflowChecker::default();
    checker.visit_file(&parsed);

    checker.has_unchecked_financial_arithmetic && !checker.has_checked_math_globally
}

#[derive(Default)]
struct OverflowChecker {
    has_unchecked_financial_arithmetic: bool,
    has_checked_math_globally: bool,
    /// Depth inside a checked_*/saturating_* call
    in_checked_call: u32,

}

impl<'ast> Visit<'ast> for OverflowChecker {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method.starts_with("checked_") || method.starts_with("saturating_")
            || method == "ok_or" || method == "try_into"
        {
            self.has_checked_math_globally = true;
            self.in_checked_call += 1;
            syn::visit::visit_expr_method_call(self, node);
            self.in_checked_call -= 1;
            return;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if self.in_checked_call > 0 {
            syn::visit::visit_expr_binary(self, node);
            return;
        }

        let is_arithmetic = matches!(
            node.op,
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_)
        );

        if is_arithmetic {
            // Check if either operand involves financial-sounding names
            let left_str = quote::quote!(#node.left).to_string().to_lowercase();
            let right_str = quote::quote!(#node.right).to_string().to_lowercase();
            let combined = format!("{} {}", left_str, right_str);

            let is_financial = ["amount", "balance", "supply", "fee", "reward",
                               "deposit", "withdraw", "lamport", "stake", "price",
                               "value", "total"]
                .iter()
                .any(|kw| combined.contains(kw));

            // Skip constant expressions like `8 + 32`
            let left_is_lit = matches!(*node.left, Expr::Lit(_));
            let right_is_lit = matches!(*node.right, Expr::Lit(_));

            if is_financial && !(left_is_lit && right_is_lit) {
                self.has_unchecked_financial_arithmetic = true;
            }
        }

        syn::visit::visit_expr_binary(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-047: Missing Access Control — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code modifies state without access control.
///
/// The AST check:
/// 1. Finds functions that call `.borrow_mut()` or `.set_*()` methods
/// 2. Verifies whether the function or its associated accounts struct
///    has Signer constraints, require! macros, or has_one checks
/// 3. Only flags if state mutation is confirmed AND no authorization exists
pub fn ast_has_missing_access_control(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = AccessControlChecker::default();
    checker.visit_file(&parsed);

    // Check interprocedural auth: if the function calls assert_*, get_*_data(program_id),
    // or accesses .is_signer, authorization exists via called functions
    if checker.has_state_mutation && !checker.has_authorization {
        // Fall through to interprocedural check
        !has_interprocedural_auth(code)
    } else {
        false
    }
}

#[derive(Default)]
struct AccessControlChecker {
    has_state_mutation: bool,
    has_authorization: bool,
}

impl<'ast> Visit<'ast> for AccessControlChecker {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        // Check if any field has signer/has_one/constraint attributes
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                for attr in &field.attrs {
                    let s = quote::quote!(#attr).to_string();
                    if s.contains("signer") || s.contains("has_one")
                        || s.contains("constraint") || s.contains("seeds")
                    {
                        self.has_authorization = true;
                    }
                }
                // Check for Signer<> type
                let type_str = quote::quote!(#field.ty).to_string();
                if type_str.contains("Signer") {
                    self.has_authorization = true;
                }
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "borrow_mut" || method.starts_with("set_") || method == "serialize" {
            self.has_state_mutation = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let mac_name = node.mac.path.segments.last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if mac_name == "require" || mac_name == "require_keys_eq"
            || mac_name == "require_eq" || mac_name == "access_control"
        {
            self.has_authorization = true;
        }
        syn::visit::visit_expr_macro(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        if let syn::Member::Named(ident) = &node.member {
            if ident == "is_signer" {
                self.has_authorization = true;
            }
        }
        syn::visit::visit_expr_field(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-030: Privilege Escalation — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code allows authority changes without current authority signing.
pub fn ast_has_privilege_escalation(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = PrivEscChecker::default();
    checker.visit_file(&parsed);

    checker.has_authority_change && !checker.has_current_authority_check
}

#[derive(Default)]
struct PrivEscChecker {
    has_authority_change: bool,
    has_current_authority_check: bool,
}

impl<'ast> Visit<'ast> for PrivEscChecker {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "set_authority" {
            self.has_authority_change = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                let field_name = field.ident.as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();

                // Check for authority field with signer/has_one
                if field_name.contains("authority") || field_name.contains("admin") {
                    let type_str = quote::quote!(#field.ty).to_string();
                    if type_str.contains("Signer") {
                        self.has_current_authority_check = true;
                    }
                    for attr in &field.attrs {
                        let s = quote::quote!(#attr).to_string();
                        if s.contains("signer") || s.contains("has_one") {
                            self.has_current_authority_check = true;
                        }
                    }
                }
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        if let syn::Member::Named(ident) = &node.member {
            if ident == "is_signer" {
                self.has_current_authority_check = true;
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        // Check if an authority field is being reassigned
        let left_str = quote::quote!(#node.left).to_string().to_lowercase();
        if left_str.contains("authority") || left_str.contains("admin") || left_str.contains("owner") {
            let right_str = quote::quote!(#node.right).to_string().to_lowercase();
            if right_str.contains(".key()") || right_str.contains("accounts.") {
                self.has_authority_change = true;
            }
        }
        syn::visit::visit_expr_assign(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-017: Reentrancy — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code has state writes AFTER CPI calls (reentrancy pattern).
///
/// Suppresses findings when:
/// - The function validates authorization before the CPI (assert_*, get_*_data)
/// - The CPI uses invoke_signed with PDA seeds (PDA is controlled, not arbitrary)
/// - State writes after CPI are recording execution results (governance pattern)
pub fn ast_has_reentrancy(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = ReentrancyChecker::default();
    checker.visit_file(&parsed);

    // If state write after CPI detected, check if context shows it's safe:
    // - invoke_signed means the CPI target is PDA-controlled (not arbitrary callback)
    // - Interprocedural auth (assert_can_execute, get_*_data) means access is gated
    if checker.has_state_write_after_cpi {
        // invoke_signed with prior validation = governance execution pattern, not reentrancy
        if checker.uses_invoke_signed && has_interprocedural_auth(code) {
            return false;
        }
        true
    } else {
        false
    }
}

#[derive(Default)]
struct ReentrancyChecker {
    has_state_write_after_cpi: bool,
    /// Tracks if we've seen a CPI call in the current function
    seen_cpi: bool,
    in_function: bool,
    /// Whether any invoke_signed call exists (PDA-controlled CPI)
    uses_invoke_signed: bool,
}

impl<'ast> Visit<'ast> for ReentrancyChecker {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.seen_cpi = false;
        self.in_function = true;
        // Visit statements in order to track CPI-then-write pattern
        for stmt in &node.block.stmts {
            self.visit_stmt(stmt);
        }
        self.in_function = false;
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.in_function {
            let call_str = quote::quote!(#node.func).to_string();
            if call_str.contains("invoke_signed") {
                self.seen_cpi = true;
                self.uses_invoke_signed = true;
            } else if call_str.contains("invoke")
                || call_str.contains("transfer") || call_str.contains("cpi")
            {
                self.seen_cpi = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if self.in_function {
            if method == "invoke_signed" {
                self.seen_cpi = true;
                self.uses_invoke_signed = true;
            } else if method == "invoke"
                || method == "transfer" || method.contains("cpi")
            {
                self.seen_cpi = true;
            }

            // State write after CPI → reentrancy
            if self.seen_cpi && (method == "borrow_mut" || method == "serialize"
                || method.starts_with("set_") || method == "save")
            {
                self.has_state_write_after_cpi = true;
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-048: Account Hijacking — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code creates accounts at keypair addresses (not PDAs).
pub fn ast_has_account_hijacking(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = HijackChecker::default();
    checker.visit_file(&parsed);

    checker.has_keypair_create && !checker.has_pda_derivation
}

#[derive(Default)]
struct HijackChecker {
    has_keypair_create: bool,
    has_pda_derivation: bool,
}

impl<'ast> Visit<'ast> for HijackChecker {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let call_str = quote::quote!(#node.func).to_string();
        if call_str.contains("create_account") {
            self.has_keypair_create = true;
        }
        if call_str.contains("find_program_address") || call_str.contains("create_program_address") {
            self.has_pda_derivation = true;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        // Check for #[account(init, seeds = ...)] which is safe PDA init
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                for attr in &field.attrs {
                    let s = quote::quote!(#attr).to_string();
                    if s.contains("init") && s.contains("seeds") {
                        self.has_pda_derivation = true;
                    }
                }
            }
        }
        syn::visit::visit_item_struct(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-003: Missing Owner Check — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code deserializes account data without verifying the owner.
pub fn ast_has_missing_owner(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = OwnerChecker::default();
    checker.visit_file(&parsed);

    checker.has_raw_deserialization && !checker.has_owner_check
}

#[derive(Default)]
struct OwnerChecker {
    has_raw_deserialization: bool,
    has_owner_check: bool,
    /// Whether we're in an anchor-style accounts struct (typed accounts check owner automatically)
    has_typed_accounts: bool,
}

impl<'ast> Visit<'ast> for OwnerChecker {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                let type_str = quote::quote!(#field.ty).to_string();

                // Anchor's Account<> type automatically checks owner
                if type_str.contains("Account <") || type_str.contains("Account<") {
                    self.has_typed_accounts = true;
                    self.has_owner_check = true;
                }

                // has_one or constraint attributes check ownership
                for attr in &field.attrs {
                    let s = quote::quote!(#attr).to_string();
                    if s.contains("has_one") || s.contains("constraint") || s.contains("owner") {
                        self.has_owner_check = true;
                    }
                }
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();

        // Raw deserialization without Anchor's type safety
        if method == "try_deserialize" || method == "try_from_slice"
            || method == "unpack" || method == "deserialize"
        {
            self.has_raw_deserialization = true;
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        if let syn::Member::Named(ident) = &node.member {
            if ident == "owner" {
                self.has_owner_check = true;
            }
        }
        syn::visit::visit_expr_field(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-005: Arbitrary CPI — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code invokes CPI without validating the target program ID.
pub fn ast_has_arbitrary_cpi(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = CpiChecker::default();
    checker.visit_file(&parsed);

    if checker.has_cpi_invoke && !checker.has_program_validation {
        // Suppress if interprocedural auth shows this is PDA-signed or validated
        // CPI invocations using invoke_signed with PDA seeds are inherently
        // controlled — the program derives the signer, not the caller
        if checker.uses_invoke_signed {
            return false;
        }
        // Also suppress if interprocedural auth (assert_*, get_*_data) is present
        !has_interprocedural_auth(code)
    } else {
        false
    }
}

#[derive(Default)]
struct CpiChecker {
    has_cpi_invoke: bool,
    has_program_validation: bool,
    /// Whether invoke_signed is used (PDA-controlled CPI)
    uses_invoke_signed: bool,
}

impl<'ast> Visit<'ast> for CpiChecker {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let call_str = quote::quote!(#node.func).to_string();
        if call_str.contains("invoke_signed") {
            self.has_cpi_invoke = true;
            self.uses_invoke_signed = true;
        } else if call_str.contains("invoke") {
            self.has_cpi_invoke = true;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "invoke_signed" {
            self.has_cpi_invoke = true;
            self.uses_invoke_signed = true;
        } else if method == "invoke" {
            self.has_cpi_invoke = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        // Check if any field uses Program<> type (validates program ID automatically)
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                let type_str = quote::quote!(#field.ty).to_string();
                if type_str.contains("Program<") || type_str.contains("Program <") {
                    self.has_program_validation = true;
                }

                // Check for #[account(address = ...)] on program fields
                for attr in &field.attrs {
                    let s = quote::quote!(#attr).to_string();
                    if s.contains("address =") || s.contains("executable") {
                        self.has_program_validation = true;
                    }
                }
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            let expr_str = quote::quote!(#node).to_string();
            if expr_str.contains("program_id") || expr_str.contains("key()") {
                self.has_program_validation = true;
            }
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Anchor detection helper
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code is an Anchor-style program with validated account structs.
///
/// Anchor programs using `#[derive(Accounts)]` with typed accounts (Account<>, Signer<>,
/// Program<>) get automatic validation. Many string-matchers fire false positives on
/// these because they look for absence of patterns that Anchor handles at the framework level.
pub fn is_anchor_validated(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut found_typed_accounts = 0;
    let mut found_signer = false;
    let mut _found_program = false;

    for item in &parsed.items {
        if let Item::Struct(s) = item {
            let is_accounts = s.attrs.iter().any(|attr| {
                let txt = quote::quote!(#attr).to_string();
                txt.contains("Accounts")
            });
            if is_accounts {
                if let Fields::Named(ref fields) = s.fields {
                    for field in &fields.named {
                        let type_str = quote::quote!(#field.ty).to_string();
                        if type_str.contains("Account<") || type_str.contains("Account <") {
                            found_typed_accounts += 1;
                        }
                        if type_str.contains("Signer") {
                            found_signer = true;
                        }
                        if type_str.contains("Program") {
                            _found_program = true;
                        }
                    }
                }
            }
        }
    }

    // An Anchor program with typed accounts, a signer, is well-validated
    found_typed_accounts > 0 && found_signer
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Test module
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_present_no_false_positive() {
        let code = r#"
            #[derive(Accounts)]
            pub struct WithdrawAccounts<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
                pub system_program: Program<'info, System>,
            }
            pub fn withdraw(ctx: Context<WithdrawAccounts>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance -= amount;
                Ok(())
            }
        "#;
        assert!(!ast_has_missing_signer(code), "Should NOT flag — Signer<> present");
    }

    #[test]
    fn test_signer_missing_true_positive() {
        let code = r#"
            #[derive(Accounts)]
            pub struct WithdrawAccounts<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
                pub system_program: Program<'info, System>,
            }
            pub fn withdraw(ctx: Context<WithdrawAccounts>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance -= amount;
                Ok(())
            }
        "#;
        assert!(ast_has_missing_signer(code), "SHOULD flag — raw AccountInfo for authority");
    }

    #[test]
    fn test_checked_math_no_false_positive() {
        let code = r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
                Ok(())
            }
        "#;
        assert!(!ast_has_integer_overflow(code), "Should NOT flag — checked_add used");
    }

    #[test]
    fn test_unchecked_math_true_positive() {
        let code = r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance = vault.balance + amount;
                Ok(())
            }
        "#;
        assert!(ast_has_integer_overflow(code), "SHOULD flag — unchecked addition on balance");
    }

    #[test]
    fn test_anchor_validated_struct() {
        let code = r#"
            #[derive(Accounts)]
            pub struct ProcessGovernance<'info> {
                #[account(mut, has_one = authority)]
                pub governance: Account<'info, Governance>,
                pub authority: Signer<'info>,
                pub system_program: Program<'info, System>,
            }
            pub fn process(ctx: Context<ProcessGovernance>) -> Result<()> {
                ctx.accounts.governance.set_authority(ctx.accounts.authority.key());
                Ok(())
            }
        "#;
        assert!(!ast_has_missing_access_control(code), "Should NOT flag — has_one + Signer");
        assert!(!ast_has_privilege_escalation(code), "Should NOT flag — current authority is Signer");
    }
}
