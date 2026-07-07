extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn debug_print(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(item as ItemFn);

    let ident = &item_fn.sig.ident;
    let vis = &item_fn.vis;
    let sig = &item_fn.sig;
    let block = &item_fn.block;
    let attrs = &item_fn.attrs;

    let expanded = quote! {
        #(#attrs)*
        #vis #sig {
            println!("Entering function: {}", stringify!(#ident));
            #block
        }
    };

    TokenStream::from(expanded)
}