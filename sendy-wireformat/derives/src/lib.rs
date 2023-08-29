use proc_macro::TokenStream;
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DataStruct, DeriveInput, Expr,
    Field, Fields, Ident, Index, LitInt, Type, Variant,
};

#[proc_macro_derive(ToBytes)]
pub fn derive_tobytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match input.data {
        Data::Struct(s) => derive_tobytes_struct(input.ident, s),
        Data::Enum(e) => derive_tobytes_enum(input.ident, &input.attrs, e),
        Data::Union(_) => panic!("Derive not supported for union types"),
    }
}

#[proc_macro_derive(FromBytes)]
pub fn derive_frombytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match input.data {
        Data::Struct(s) => derive_frombytes_struct(input.ident, s),
        Data::Enum(e) => derive_frombytes_enum(input.ident, &input.attrs, e),
        Data::Union(_) => panic!("Derive not supported for union types"),
    }
}

fn derive_tobytes_enum(ident: Ident, attr: &[Attribute], data: DataEnum) -> TokenStream {
    let (_, discriminant) = variant_name_discriminant_iter(data.variants.iter());
    let variant_match = data.variants.iter().map(empty_constructor_of);
    let variant_match2 = variant_match.clone();

    let impl_variant = data.variants.iter().map(|variant| {
        let (name, ty) = field_rawname_type_iter(variant.fields.iter());

        quote! {
            #( <#ty as ::sendy_wireformat::ToBytes>::encode::<B>(&#name, buf)?; )*
        }
    });

    let impl_variant_size = data.variants.iter().map(|variant| {
        let (name, ty) = field_rawname_type_iter(variant.fields.iter());

        quote! {
            #( + <#ty as ::sendy_wireformat::ToBytes>::size_hint(&#name) )*
        }
    });

    let implementation = quote! {
        impl ::sendy_wireformat::ToBytes for #ident {
            fn encode<B: ::sendy_wireformat::ByteWriter>(&self, buf: &mut B) -> ::core::result::Result<(), ::sendy_wireformat::ToBytesError> {
                match self {
                    #( Self::#variant_match => {
                        <u8 as ::sendy_wireformat::ToBytes>::encode(&#discriminant, buf)?;
                        #impl_variant
                    }),*
                }

                Ok(())
            }

            fn size_hint(&self) -> usize {
                match self {
                    #( Self::#variant_match2 => <u8 as ::sendy_wireformat::ToBytes>::size_hint(&#discriminant) #impl_variant_size ),*
                }
            }
        }
    };

    TokenStream::from(implementation)
}

fn derive_frombytes_enum(ident: Ident, attr: &[Attribute], data: DataEnum) -> TokenStream {
    let (_, discriminant) = variant_name_discriminant_iter(data.variants.iter());

    let impl_variant = data.variants.iter().map(|variant| {
        let (name, ty) = field_rawname_type_iter(variant.fields.iter());
        let constructor = constructor_of(&variant.ident, &variant.fields);

        quote! {
            #( let #name = <#ty as ::sendy_wireformat::FromBytes<'a>>::decode(reader)?; )*
            Ok(Self::#constructor)
        }
    });

    let errormsg = format!("Invalid tag for {}", ident);

    let implementation = quote! {
        impl<'a> ::sendy_wireformat::FromBytes<'a> for #ident {
            fn decode(reader: &mut ::sendy_wireformat::untrusted::Reader<'a>) -> ::core::result::Result<Self, ::sendy_wireformat::FromBytesError> {
                let tag = <u8 as ::sendy_wireformat::FromBytes<'a>>::decode(reader)?;

                match tag {
                    #( #discriminant => { #impl_variant }),*
                    _ => ::core::result::Result::<Self, ::sendy_wireformat::FromBytesError>::Err(::sendy_wireformat::FromBytesError::Parsing(
                        <::std::string::String as ::core::convert::From<&'static str>>::from(#errormsg)
                    ))
                }
            }
        }
    };

    TokenStream::from(implementation)
}

/// Get the variant names and their assigned tags
fn variant_name_discriminant_iter<'a>(
    variants: impl Iterator<Item = &'a Variant>,
) -> (Vec<Ident>, Vec<Expr>) {
    variants
        .map(|variant| {
            (
                variant.ident.clone(),
                match variant.discriminant.clone() {
                    Some((_, disc)) => disc,
                    None => match variant.attrs.iter().find(|attr| {
                        attr.meta
                            .path()
                            .get_ident()
                            .map(|i| i == "wiretag")
                            .unwrap_or(false)
                    }) {
                        Some(attr) => match attr.parse_args::<LitInt>() {
                            Ok(lit) => Expr::Lit(syn::ExprLit {
                                attrs: vec![],
                                lit: syn::Lit::Int(lit),
                            }),
                            Err(e) => {
                                panic!("Invalid enum tag for variant {}: {}", variant.ident, e)
                            }
                        },
                        None => panic!(
                            "Variant {} has no 'wiretag' attribute or discriminant assignment",
                            variant.ident
                        ),
                    },
                },
            )
        })
        .unzip()
}
/// Get field names or indexes to use when referencing the field of a struct
fn field_name_type_iter<'a>(
    fields: impl Iterator<Item = &'a Field>,
) -> (Vec<TokenStream2>, Vec<Type>) {
    fields
        .enumerate()
        .map(|(idx, v)| {
            (
                v.ident
                    .clone()
                    .map(|i| i.to_token_stream())
                    .unwrap_or(Index::from(idx).to_token_stream()),
                v.ty.clone(),
            )
        })
        .unzip::<_, _, Vec<_>, Vec<_>>()
}

/// Get field names or indexes to use when constructing a struct
///
/// differs from `field_name_type_iter` in that indexes of a tuple struct are returned as '_0'
/// idents and not '0' literals e.g. they cannot be used to access a field as `self.#ident`, but
/// they can be used to construct a tuple struct
fn field_rawname_type_iter<'a>(fields: impl Iterator<Item = &'a Field>) -> (Vec<Ident>, Vec<Type>) {
    fields
        .enumerate()
        .map(|(idx, v)| {
            (
                v.ident
                    .clone()
                    .unwrap_or(Ident::new(&*format!("_{}", idx), v.span())),
                v.ty.clone(),
            )
        })
        .unzip::<_, _, Vec<_>, Vec<_>>()
}

/// Get a constructor expression for the given struct type, variables must be named
fn constructor_of(ident: &Ident, fields: &Fields) -> TokenStream2 {
    let is_named = matches!(fields, Fields::Named(_));
    let is_unit = !is_named && fields.len() == 0;
    let (name, _) = field_rawname_type_iter(fields.into_iter());

    match is_named {
        true => quote! { #ident { #(#name),* } },
        false => match is_unit {
            true => quote! { #ident },
            false => quote! { #ident(#(#name),*) },
        },
    }
}

fn derive_tobytes_struct(ident: Ident, data: DataStruct) -> TokenStream {
    let (name, ty) = field_name_type_iter(data.fields.iter());

    let implementation = quote! {
        impl ::sendy_wireformat::ToBytes for #ident {
            fn encode<B: ::sendy_wireformat::ByteWriter>(&self, writer: &mut B) -> ::core::result::Result<(), ::sendy_wireformat::ToBytesError> {
                #( <#ty as ::sendy_wireformat::ToBytes>::encode(&self.#name, writer)?; )*
                ::core::result::Result::<(), ::sendy_wireformat::ToBytesError>::Ok(())
            }

            fn size_hint(&self) -> usize {
                0 + #( <#ty as ::sendy_wireformat::ToBytes>::size_hint(&self.#name) )+*
            }
        }
    };

    TokenStream::from(implementation)
}

/// Create a match pattern that will match on any value of the given variant
fn empty_constructor_of(variant: &Variant) -> TokenStream2 {
    let is_named = matches!(variant.fields, Fields::Named(_));
    let is_unit = !is_named && variant.fields.len() == 0;
    let (name, _) = field_rawname_type_iter(variant.fields.iter());

    let ident = &variant.ident;

    match is_named {
        true => quote! { #ident { #(#name),* } },
        false => match is_unit {
            true => quote! { #ident },
            false => quote! { #ident(#(#name),*) },
        },
    }
}

fn derive_frombytes_struct(ident: Ident, data: DataStruct) -> TokenStream {
    let (name, ty) = field_rawname_type_iter(data.fields.iter());

    let constructor = constructor_of(&ident, &data.fields);

    let implementation = quote! {
        impl<'a> ::sendy_wireformat::FromBytes<'a> for #ident {
            fn decode(reader: &mut ::sendy_wireformat::untrusted::Reader<'a>) -> ::core::result::Result<Self, ::sendy_wireformat::FromBytesError> {
                #( let #name = <#ty as ::sendy_wireformat::FromBytes<'a>>::decode(reader)?; )*

                Ok(#constructor)
            }
        }
    };

    TokenStream::from(implementation)
}
