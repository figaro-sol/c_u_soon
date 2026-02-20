use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields};

#[proc_macro_derive(TypeHash)]
pub fn derive_type_hash(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_type_hash_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_type_hash_impl(input: DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    if !has_repr_c(&input.attrs) {
        return Err(syn::Error::new(
            input.ident.span(),
            "TypeHash requires #[repr(C)] for deterministic field layout",
        ));
    }

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new(
                    input.ident.span(),
                    "TypeHash only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.ident.span(),
                "TypeHash only supports structs",
            ))
        }
    };

    let mut hash_expr: TokenStream2 =
        quote! { ::c_u_soon::const_fnv1a(stringify!(#name).as_bytes()) };

    for field in fields.iter() {
        let field_ty = &field.ty;
        hash_expr = quote! {
            ::c_u_soon::combine_hash(
                #hash_expr,
                <#field_ty as ::c_u_soon::TypeHash>::TYPE_HASH,
            )
        };
    }

    let expanded = quote! {
        impl ::c_u_soon::TypeHash for #name {
            const TYPE_HASH: u64 = #hash_expr;
            const METADATA: ::c_u_soon::StructMetadata = {
                assert!(
                    ::core::mem::size_of::<Self>() <= 255,
                    "TypeHash: struct size exceeds u8 max"
                );
                ::c_u_soon::StructMetadata::new(
                    ::core::mem::size_of::<Self>() as u8,
                    Self::TYPE_HASH,
                )
            };
        }
    };

    Ok(expanded)
}

fn has_repr_c(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("repr") {
            if let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) {
                for meta in &nested {
                    if let syn::Meta::Path(path) = meta {
                        if path.is_ident("C") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}
