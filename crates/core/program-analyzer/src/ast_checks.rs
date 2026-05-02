use quote::quote;
use syn::visit::Visit;
use syn::{BinOp, ExprBinary, ExprCall, ExprField, ExprMethodCall, Fields, ItemFn, ItemStruct};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Helper: Interprocedural Auth Detection
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if the code uses common interprocedural validation patterns.
fn has_interprocedural_auth(code: &str) -> bool {
    let lower = code.to_lowercase();
    lower.contains("assert_") || lower.contains("validate_") || lower.contains("get_account_data")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-020: Price Stale Data — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn ast_has_stale_oracle(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = OracleStalenessChecker::default();
    checker.visit_file(&parsed);

    checker.has_oracle_usage && !checker.has_freshness_check
}

#[derive(Default)]
struct OracleStalenessChecker {
    has_oracle_usage: bool,
    has_freshness_check: bool,
}

impl<'ast> Visit<'ast> for OracleStalenessChecker {
    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        let field = if let syn::Member::Named(ident) = &node.member {
            ident.to_string().to_lowercase()
        } else {
            String::new()
        };

        if ["price", "aggregator", "oracle", "pyth", "switchboard"].iter().any(|&k| field.contains(k)) {
            self.has_oracle_usage = true;
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let left = quote::quote!(#node.left).to_string().to_lowercase();
        let right = quote::quote!(#node.right).to_string().to_lowercase();
        let combined = format!("{} {}", left, right);

        if (combined.contains("timestamp") || combined.contains("slot"))
            && matches!(node.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_))
        {
            self.has_freshness_check = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-DEEP-CPI: Reload Accounts after CPI
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn ast_missing_cpi_reload(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = CpiReloadChecker::default();
    checker.visit_file(&parsed);

    checker.has_cpi_call && checker.has_post_cpi_usage && !checker.has_reload_call
}

#[derive(Default)]
struct CpiReloadChecker {
    has_cpi_call: bool,
    has_post_cpi_usage: bool,
    has_reload_call: bool,
    seen_cpi: bool,
}

impl<'ast> Visit<'ast> for CpiReloadChecker {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let func = quote::quote!(#node.func).to_string();
        if func.contains("invoke") || func.contains("CpiContext") {
            self.has_cpi_call = true;
            self.seen_cpi = true;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "reload" {
            self.has_reload_call = true;
        } else if self.seen_cpi && (method == "borrow" || method == "borrow_mut" || method == "key") {
            self.has_post_cpi_usage = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-004: Type Cosplay / Discriminator Bypass — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn ast_has_type_cosplay(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = TypeCosplayChecker::default();
    checker.visit_file(&parsed);

    checker.has_raw_deserialization && !checker.has_discriminator_check
}

#[derive(Default)]
struct TypeCosplayChecker {
    has_raw_deserialization: bool,
    has_discriminator_check: bool,
}

impl<'ast> Visit<'ast> for TypeCosplayChecker {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "try_from_slice" || method == "deserialize" {
            self.has_raw_deserialization = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let name = node.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if name == "require" || name == "assert" {
            let tokens = quote::quote!(#node).to_string().to_lowercase();
            if tokens.contains("discriminator") || tokens.contains("type") {
                self.has_discriminator_check = true;
            }
        }
        syn::visit::visit_expr_macro(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let left = quote::quote!(#node.left).to_string().to_lowercase();
        if left.contains("discriminator") || left.contains("type") {
            self.has_discriminator_check = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SOL-030: Privilege Escalation — AST version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
        if method.contains("set_authority") || method.contains("change_owner") {
            self.has_authority_change = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let name = node.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if name == "require" || name == "assert" {
            let tokens = quote::quote!(#node).to_string().to_lowercase();
            if tokens.contains("signer") || tokens.contains("authority") {
                self.has_current_authority_check = true;
            }
        }
        syn::visit::visit_expr_macro(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                let field_name = field.ident.as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();

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

pub fn ast_has_reentrancy(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = ReentrancyChecker::default();
    checker.visit_file(&parsed);

    if checker.has_state_write_after_cpi {
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
    seen_cpi: bool,
    in_function: bool,
    uses_invoke_signed: bool,
}

impl<'ast> Visit<'ast> for ReentrancyChecker {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.seen_cpi = false;
        self.in_function = true;
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
    has_typed_accounts: bool,
}

impl<'ast> Visit<'ast> for OwnerChecker {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if let Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                let type_str = quote::quote!(#field.ty).to_string();
                if type_str.contains("Account <") || type_str.contains("Account<") {
                    self.has_typed_accounts = true;
                    self.has_owner_check = true;
                }
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

pub fn ast_has_arbitrary_cpi(code: &str) -> bool {
    let parsed = match syn::parse_file(code) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut checker = CpiChecker::default();
    checker.visit_file(&parsed);

    if checker.has_cpi_invoke && !checker.has_program_validation {
        if checker.uses_invoke_signed {
            return false;
        }
        !has_interprocedural_auth(code)
    } else {
        false
    }
}

#[derive(Default)]
struct CpiChecker {
    has_cpi_invoke: bool,
    has_program_validation: bool,
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

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let left = quote::quote!(#node.left).to_string().to_lowercase();
        if left.contains("program_id") || left.contains("target_program") {
            self.has_program_validation = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }
}
