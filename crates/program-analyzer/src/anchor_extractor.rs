use quote::ToTokens;
use syn::{Attribute, ItemFn, ItemStruct};

pub struct AnchorExtractor;

impl AnchorExtractor {
    pub fn is_anchor_account(s: &ItemStruct) -> bool {
        Self::has_macro_attribute(&s.attrs, "account")
    }

    pub fn is_instruction_context(s: &ItemStruct) -> bool {
        // Often #[derive(Accounts)]
        s.attrs.iter().any(|attr| {
            if attr.path().is_ident("derive") {
                let code = attr.to_token_stream().to_string();
                code.contains("Accounts")
            } else {
                false
            }
        })
    }

    pub fn is_program_module(f: &ItemFn) -> bool {
        // Check for #[program] attribute on the function
        if Self::has_macro_attribute(&f.attrs, "program") {
            return true;
        }

        // Detect Anchor instruction handlers by signature pattern:
        // pub fn handler(ctx: Context<...>, ...) -> Result<()>
        let sig = f.sig.to_token_stream().to_string();
        let has_context_param = sig.contains("Context <") || sig.contains("Context<");
        let has_result_return = sig.contains("Result <") || sig.contains("Result<");
        let is_pub = matches!(f.vis, syn::Visibility::Public(_));

        is_pub && has_context_param && has_result_return
    }

    fn has_macro_attribute(attrs: &[Attribute], name: &str) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident(name))
    }
}
