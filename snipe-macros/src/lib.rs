use proc_macro::{TokenStream, Ident};
use quote::quote;

#[proc_macro]
pub fn declare_mib(item: TokenStream) -> TokenStream {
    let ident: Ident = item.parse();
    quote! {}
}