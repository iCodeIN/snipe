use convert_case::{Case, Casing};
use quote::quote;
use syn::{parse::Parse, parse_macro_input, spanned::Spanned, Ident, Lit, Token, Type};

#[proc_macro]
pub fn declare_mib(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as Lit);
    let input_span = input.span();
    if let Lit::Str(mib_name_lit) = input {
        let mib_name_string = mib_name_lit.value();
        let mut mib_name = mib_name_string.as_str();
        if mib_name.ends_with(".mib") {
            mib_name = &mib_name[..mib_name.len() - 4];
        }

        let pascal_mib_name = mib_name.to_case(Case::Pascal);
        let struct_name = Ident::new(pascal_mib_name.as_str(), input_span);
        let get_trait_name = Ident::new(format!("Get{pascal_mib_name}").as_str(), input_span);
        let method_name: Ident = Ident::new(mib_name.to_case(Case::Snake).as_str(), input_span);
        quote! {
            pub struct #struct_name<'a, I: ::snipe::SnmpInterface>(&'a mut I);
            impl<'a, I: ::snipe::SnmpInterface> ::snipe::GetSnmpInterface for #struct_name<'a, I> {
                type Interface = I;

                fn snmp_interface(&mut self) -> &mut Self::Interface {
                    self.0
                }
            }

            pub trait #get_trait_name {
                type Interface: ::snipe::SnmpInterface;
                fn #method_name<'a>(&'a mut self) -> #struct_name<'a, Self::Interface>;
            }

            impl<T: SnmpInterface> #get_trait_name for T {
                type Interface = T;

                fn #method_name<'a>(&'a mut self) -> #struct_name<'a, Self::Interface> {
                    #struct_name(self.snmp_interface())
                }
            }
        }
        .into()
    } else {
        proc_macro::TokenStream::new()
    }
}

struct DeclareOid {
    oid_name: Lit,
    _separator: Token![,],
    type_name: Type,
}

impl Parse for DeclareOid {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Self {
            oid_name: input.parse()?,
            _separator: input.parse()?,
            type_name: input.parse()?,
        })
    }
}

#[proc_macro]
pub fn declare_oid(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as DeclareOid);
    let oid_name_span = input.oid_name.span();
    let type_name = input.type_name;
    if let Lit::Str(oid_name_lit) = input.oid_name {
        let oid_name = oid_name_lit.value();
        let pascal_mib_name = oid_name.to_case(Case::Pascal);
        let snake_oid_name = oid_name.to_case(Case::Snake);
        let read_trait_name = Ident::new(format!("Read{pascal_mib_name}").as_str(), oid_name_span);
        let read_indexed_trait_name = Ident::new(
            format!("Read{pascal_mib_name}Indexed").as_str(),
            oid_name_span,
        );
        let write_trait_name =
            Ident::new(format!("Write{pascal_mib_name}").as_str(), oid_name_span);
        let write_indexed_trait_name = Ident::new(
            format!("Write{pascal_mib_name}Indexed").as_str(),
            oid_name_span,
        );
        let get_method_name: Ident = Ident::new(snake_oid_name.as_str(), oid_name_span);
        let set_method_name: Ident =
            Ident::new(format!("set_{snake_oid_name}").as_str(), oid_name_span);
        quote! {
            pub trait #read_trait_name: Sized + ::snipe::GetSnmpInterface {
                type Converter: ::snipe::prelude::SnmpConverter<#type_name>;
                const OID: ::snipe::asn::types::ConstOid;
                fn #get_method_name(&mut self) -> Result<#type_name, ::snipe::Error> {
                    <Self::Converter as ::snipe::prelude::SnmpConverter<#type_name>>::try_from_snmp(
                        ::snipe::SnmpInterface::read(
                            snipe::GetSnmpInterface::snmp_interface(self),
                            Self::OID.into()
                        )?
                    )
                }
            }
            pub trait #read_indexed_trait_name: Sized + ::snipe::GetSnmpInterface {
                type Index;
                type Converter: ::snipe::prelude::SnmpConverter<#type_name>;
                type IndexConverter: ::snipe::prelude::SnmpConverter<Self::Index>;
                const OID: ::snipe::asn::types::ConstOid;
                fn #get_method_name(&mut self, index: Self::Index) -> Result<#type_name, ::snipe::Error> {
                    todo!()
                }
            }
            pub trait #write_trait_name: Sized + ::snipe::GetSnmpInterface {
                const OID: ::snipe::asn::types::ConstOid;
                fn #set_method_name(&mut self, value: #type_name) -> Result<(), ::snipe::Error> {
                    todo!()
                }
            }
            pub trait #write_indexed_trait_name: Sized + ::snipe::GetSnmpInterface {
                type Index;
                type Converter: ::snipe::prelude::SnmpConverter<#type_name>;
                type IndexConverter: ::snipe::prelude::SnmpConverter<Self::Index>;
                const OID: ::snipe::asn::types::ConstOid;
                fn #set_method_name(&mut self, index: Self::Index, value: #type_name) -> Result<(), ::snipe::Error> {
                    todo!()
                }
            }
        }.into()
    } else {
        proc_macro::TokenStream::new()
    }
}
