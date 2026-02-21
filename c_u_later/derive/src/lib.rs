//! Proc-macro crate that provides `#[derive(CuLater)]` for [`c_u_later`].

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Type};

/// Derives [`c_u_later::CuLaterMask`] and [`c_u_soon::TypeHash`] for a `#[repr(C)]` struct.
///
/// # Field attributes
///
/// - `#[program]`: includes this field's bytes in `program_mask()`.
/// - `#[authority]`: includes this field's bytes in `authority_mask()`.
/// - `#[embed]` — for fields whose type does not implement `CuLaterMask`. Marks every byte
///   of the field writable without sub-field granularity. The field type must be
///   `Pod + Zeroable`. If the type implements `CuLater`, calling `program_mask()` or
///   `authority_mask()` panics; remove `#[embed]` and let the type's own mask compose
///   recursively instead.
///
/// Fields without any attribute are read-only from both callers' perspectives.
///
/// # Mask composition (without `#[embed]`)
///
/// For `#[program]` / `#[authority]` fields whose type implements `CuLaterMask`, the
/// derive calls `FieldType::program_mask()` or `FieldType::authority_mask()` and splices
/// the result into the parent mask at the field's byte offset. Primitive integer types
/// and fixed-size arrays of `CuLaterMask` types have built-in impls (all bytes writable),
/// so they work as field types without `#[embed]`.
///
/// # Generated items
///
/// - `impl CuLaterMask for MyStruct`: `program_mask()` and `authority_mask()` each return
///   `Vec<bool>` of length `size_of::<MyStruct>()` where `true` = writable, `false` = blocked.
/// - A const assertion that `size_of::<MyStruct>() <= AUX_SIZE` (255 bytes).
///
/// # Requirements
///
/// - `#[repr(C)]` is required for deterministic field layout.
/// - Only named-field structs are supported.
/// - `#[program]` / `#[authority]` fields without `#[embed]` must implement `CuLaterMask`.
/// - `#[embed]` field types must be `Pod + Zeroable`.
///
/// # Example
///
/// ```rust,ignore
/// use bytemuck::{Pod, Zeroable};
/// use c_u_later::CuLater;
///
/// #[derive(Clone, Copy, Pod, Zeroable, CuLater)]
/// #[repr(C)]
/// struct OracleSlot {
///     readonly_header: u32,
///     #[program]
///     counter: u32,
///     #[authority]
///     config: u32,
///     #[program]
///     #[authority]
///     shared: u32,
/// }
/// // program_mask():   bytes 4-7 and 12-15 are writable
/// // authority_mask(): bytes 8-11 and 12-15 are writable
/// ```
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
    let vis = &input.vis;

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

    let program_wrapper = generate_wrapper(name, vis, &field_infos, "Program", true);
    let authority_wrapper = generate_wrapper(name, vis, &field_infos, "Authority", false);

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
        fn #program_mask_fn() -> ::c_u_later::__private::Vec<bool> {
            #[allow(unused_imports)]
            use ::c_u_later::IsNotCuLater as _;
            let mut mask = ::c_u_later::__private::vec![false; ::core::mem::size_of::<#name>()];
            #(#program_mask_parts)*
            mask
        }

        #[doc(hidden)]
        fn #authority_mask_fn() -> ::c_u_later::__private::Vec<bool> {
            #[allow(unused_imports)]
            use ::c_u_later::IsNotCuLater as _;
            let mut mask = ::c_u_later::__private::vec![false; ::core::mem::size_of::<#name>()];
            #(#authority_mask_parts)*
            mask
        }

        impl ::c_u_later::CuLaterMask for #name {
            fn program_mask() -> ::c_u_later::__private::Vec<bool> {
                #program_mask_fn()
            }

            fn authority_mask() -> ::c_u_later::__private::Vec<bool> {
                #authority_mask_fn()
            }
        }

        #program_wrapper
        #authority_wrapper
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

const PRIMITIVE_NAMES: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "f32", "f64", "bool",
];

fn is_primitive_or_array(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => {
            if let Some(ident) = type_path.path.get_ident() {
                let s = ident.to_string();
                return PRIMITIVE_NAMES.contains(&s.as_str());
            }
            false
        }
        Type::Array(_) => true,
        _ => false,
    }
}

fn is_padding_field(name: &syn::Ident) -> bool {
    name.to_string().starts_with('_')
}

fn build_wrapper_path(ty: &Type, suffix: &str) -> Option<syn::Path> {
    if let Type::Path(type_path) = ty {
        let mut path = type_path.path.clone();
        if let Some(last) = path.segments.last_mut() {
            last.ident = format_ident!("{}{}", last.ident, suffix);
            last.arguments = syn::PathArguments::None;
        }
        Some(path)
    } else {
        None
    }
}

fn generate_wrapper(
    struct_name: &syn::Ident,
    vis: &syn::Visibility,
    fields: &[FieldInfo],
    suffix: &str,
    is_program: bool,
) -> TokenStream2 {
    let wrapper_name = format_ident!("{}{}", struct_name, suffix);

    let mut accessors = Vec::new();

    for field in fields {
        let included = if is_program {
            field.has_program
        } else {
            field.has_authority
        };
        if !included || is_padding_field(&field.name) {
            continue;
        }

        let field_name = &field.name;
        let accessor_name = format_ident!("{}_mut", field_name);
        let field_ty = &field.ty;

        if !field.has_embed && !is_primitive_or_array(field_ty) {
            if let Some(wrapper_path) = build_wrapper_path(field_ty, suffix) {
                accessors.push(quote! {
                    #vis fn #accessor_name(&mut self) -> #wrapper_path<'_> {
                        #wrapper_path::from_mut(&mut self.0.#field_name)
                    }
                });
            } else {
                accessors.push(quote! {
                    #vis fn #accessor_name(&mut self) -> &mut #field_ty {
                        &mut self.0.#field_name
                    }
                });
            }
        } else {
            accessors.push(quote! {
                #vis fn #accessor_name(&mut self) -> &mut #field_ty {
                    &mut self.0.#field_name
                }
            });
        }
    }

    quote! {
        #vis struct #wrapper_name<'a>(&'a mut #struct_name);

        impl ::core::ops::Deref for #wrapper_name<'_> {
            type Target = #struct_name;

            fn deref(&self) -> &#struct_name {
                &*self.0
            }
        }

        impl<'a> #wrapper_name<'a> {
            #vis fn from_mut(inner: &'a mut #struct_name) -> Self {
                Self(inner)
            }

            #(#accessors)*
        }
    }
}
