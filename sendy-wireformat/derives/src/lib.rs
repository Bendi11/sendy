use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{parse_macro_input, DeriveInput, Data, Fields, Field, Ident, Index, Type, DataStruct};
use proc_macro2::TokenStream as TokenStream2;


#[proc_macro_derive(ToBytes)]
pub fn derive_tobytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match input.data {
        Data::Struct(s) => derive_tobytes_struct(input.ident, s),
        Data::Enum(e) => unimplemented!(),
        Data::Union(_) => panic!("Derive not supported for union types"),
    }
}

#[proc_macro_derive(FromBytes)]
pub fn derive_frombytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match input.data {
        Data::Struct(s) => derive_frombytes_struct(input.ident, s),
        Data::Enum(e) => unimplemented!(),
        Data::Union(_) => panic!("Derive not supported for union types"),
    }
}

fn field_name_type_iter(fields: impl Iterator<Item = Field>) -> (Vec<TokenStream2>, Vec<Type>) {
    fields
        .enumerate()
        .map(|(idx, v)| (
                v
                    .ident
                    .map(|i| i.to_token_stream())
                    .unwrap_or(Index::from(idx).to_token_stream()),
                v.ty 
            )
        ).unzip::<_, _, Vec<_>, Vec<_>>()
}

fn derive_tobytes_struct(ident: Ident, data: DataStruct) -> TokenStream {
    let (name, ty) = field_name_type_iter(data.fields.into_iter());

    let implementation = quote !{
        impl ::sendy_wireformat::ToBytes for #ident {
            fn encode<B: ::sendy_wireformat::ByteWriter>(&self, writer: &mut B) -> ::core::result::Result<(), ::sendy_wireformat::ToBytesError> {
                #( <#ty as ::sendy_wireformat::ToBytes>::encode(&self.#name, writer)?; )*
                ::core::result::Result::<(), ::sendy_wireformat::ToBytesError>::Ok(())
            }
        }
    };

    TokenStream::from(implementation)
}

fn derive_frombytes_struct(ident: Ident, data: DataStruct) -> TokenStream {
    let is_named = matches!(data.fields, Fields::Named(_));
    let is_unit = !is_named && data.fields.len() == 0;
    let (name, ty) = field_name_type_iter(data.fields.into_iter());

    let constructor = match is_named {
        true => quote!{ #ident { #(#name),* } },
        false => match is_unit {
            true => quote!{ #ident },
            false => quote!{ #ident(#(#name),*) },
        }
    };

    let implementation = quote !{
        impl<'a> ::sendy_wireformat::FromBytes<'a> for #ident {
            fn decode(reader: &mut ::sendy_wireformat::untrusted::Reader<'a>) -> ::core::result::Result<Self, ::sendy_wireformat::FromBytesError> {
                #( let #name = <#ty as ::sendy_wireformat::FromBytes<'a>>::decode(reader)?; )*
                
                Ok(#constructor) 
            }
        }
    };

    TokenStream::from(implementation)
}
