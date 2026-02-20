use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Type};

#[proc_macro_derive(CuLater, attributes(program, authority, embed))]
pub fn derive_cu_later(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_cu_later_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_cu_later_impl(input: DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    if !has_repr_c(&input.attrs) {
        return Err(syn::Error::new(
            input.ident.span(),
            "CuLater requires #[repr(C)] for deterministic field layout",
        ));
    }

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new(
                    input.ident.span(),
                    "CuLater only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.ident.span(),
                "CuLater only supports structs",
            ))
        }
    };

    let mut field_infos = Vec::new();
    for field in fields.iter() {
        let field_name = field.ident.as_ref().unwrap();
        let field_ty = &field.ty;
        let has_program = has_attr(&field.attrs, "program");
        let has_authority = has_attr(&field.attrs, "authority");
        let has_embed = has_attr(&field.attrs, "embed");

        field_infos.push(FieldInfo {
            name: field_name.clone(),
            ty: field_ty.clone(),
            has_program,
            has_authority,
            has_embed,
        });
    }

    let program_mask_parts: Vec<TokenStream2> = field_infos
        .iter()
        .map(|f| {
            let field_name = &f.name;
            let field_ty = &f.ty;

            if f.has_program {
                if f.has_embed {
                    quote! {
                        {
                            if ::c_u_later::IsCuLaterWrapper::<#field_ty>::is_cu_later() {
                                panic!(
                                    "Field '{}' has #[embed] but type {} implements CuLater. \
                                     Remove #[embed] to preserve fine-grained bitmask control.",
                                    stringify!(#field_name),
                                    ::core::any::type_name::<#field_ty>()
                                );
                            }
                            let offset = ::core::mem::offset_of!(#name, #field_name);
                            let size = ::core::mem::size_of::<#field_ty>();
                            for i in 0..size {
                                mask[offset + i] = true;
                            }
                        }
                    }
                } else {
                    quote! {
                        {
                            let offset = ::core::mem::offset_of!(#name, #field_name);
                            let child_mask = <#field_ty as ::c_u_later::CuLaterMask>::program_mask();
                            ::c_u_later::compose_mask_at_offset(&mut mask, &child_mask, offset);
                        }
                    }
                }
            } else {
                quote! {}
            }
        })
        .collect();

    let authority_mask_parts: Vec<TokenStream2> = field_infos
        .iter()
        .map(|f| {
            let field_name = &f.name;
            let field_ty = &f.ty;

            if f.has_authority {
                if f.has_embed {
                    quote! {
                        {
                            if ::c_u_later::IsCuLaterWrapper::<#field_ty>::is_cu_later() {
                                panic!(
                                    "Field '{}' has #[embed] but type {} implements CuLater. \
                                     Remove #[embed] to preserve fine-grained bitmask control.",
                                    stringify!(#field_name),
                                    ::core::any::type_name::<#field_ty>()
                                );
                            }
                            let offset = ::core::mem::offset_of!(#name, #field_name);
                            let size = ::core::mem::size_of::<#field_ty>();
                            for i in 0..size {
                                mask[offset + i] = true;
                            }
                        }
                    }
                } else {
                    quote! {
                        {
                            let offset = ::core::mem::offset_of!(#name, #field_name);
                            let child_mask = <#field_ty as ::c_u_later::CuLaterMask>::authority_mask();
                            ::c_u_later::compose_mask_at_offset(&mut mask, &child_mask, offset);
                        }
                    }
                }
            } else {
                quote! {}
            }
        })
        .collect();

    let name_snake = to_snake_case(&name.to_string());
    let program_mask_fn = format_ident!("__cu_later_program_mask_{}", name_snake);
    let authority_mask_fn = format_ident!("__cu_later_authority_mask_{}", name_snake);
    let expanded = quote! {
        const _: () = {
            if ::core::mem::size_of::<#name>() > ::c_u_later::AUX_SIZE {
                panic!("CuLater struct exceeds maximum auxiliary data size");
            }
        };

        #[doc(hidden)]
        fn #program_mask_fn() -> [bool; ::c_u_later::AUX_SIZE] {
            #[allow(unused_imports)]
            use ::c_u_later::IsNotCuLater as _;
            let mut mask = [false; ::c_u_later::AUX_SIZE];
            #(#program_mask_parts)*
            mask
        }

        #[doc(hidden)]
        fn #authority_mask_fn() -> [bool; ::c_u_later::AUX_SIZE] {
            #[allow(unused_imports)]
            use ::c_u_later::IsNotCuLater as _;
            let mut mask = [false; ::c_u_later::AUX_SIZE];
            #(#authority_mask_parts)*
            mask
        }

        impl ::c_u_later::CuLaterMask for #name {
            fn program_mask() -> [bool; ::c_u_later::AUX_SIZE] {
                #program_mask_fn()
            }

            fn authority_mask() -> [bool; ::c_u_later::AUX_SIZE] {
                #authority_mask_fn()
            }
        }
    };

    Ok(expanded)
}

struct FieldInfo {
    name: syn::Ident,
    ty: Type,
    has_program: bool,
    has_authority: bool,
    has_embed: bool,
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

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}
