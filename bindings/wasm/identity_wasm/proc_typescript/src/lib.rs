// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use proc_macro::TokenStream;

use darling::FromField;
use darling::FromMeta;
use quote::quote;
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::AttributeArgs;
use syn::Fields;
use syn::ItemStruct;

#[derive(Debug, FromMeta)]
struct InterfaceArguments {
  /// Name of the TypeScript interface. Otherwise use the struct identifier.
  name: Option<String>,

  /// Whether all fields should be marked as optional. Can be overridden per field.
  optional: darling::util::Flag,
  /// Whether all fields should be marked as readonly. Can be overridden per field.
  readonly: darling::util::Flag,
}

#[derive(Debug, FromField)]
#[darling(attributes(typescript))]
struct FieldArguments {
  /// Name of the TypeScript field. Otherwise use the field identifier.
  name: Option<String>,
  /// Type of the TypeScript field.
  #[darling(rename = "type")]
  ts_type: Option<String>,
  /// Whether the field should be marked as an optional property with a question mark.
  /// E.g. "name?: type".
  optional: Option<bool>,
  /// Whether the field should be marked as readonly.
  /// E.g. "readonly name: type".
  readonly: Option<bool>,
}

/// Extracts the doc-comment, if present, from a list of attributes.
///
/// NOTE: merges multiple lines, removing linebreaks for now...
///
/// E.g.
/// ```
/// /// Doc-comment for `Foo`.
/// struct Foo {}
/// ```
/// will return: `"Doc-comment for `Foo`."`.
///
/// Also supports the `#[doc = "Some comment"]` syntax, which `///` is transformed into.
fn extract_doc_comment(attributes: &[syn::Attribute]) -> Option<String> {
  let doc_comment: String = attributes
    .iter()
    .filter_map(|attribute| {
      let meta = attribute.parse_meta().ok()?;
      if let syn::Meta::NameValue(meta) = meta {
        if let syn::Lit::Str(doc_str) = meta.lit {
          return Some(doc_str.value().trim().to_owned());
        }
      }
      None
    })
    .collect::<Vec<String>>()
    .join(" ");

  if doc_comment.is_empty() {
    None
  } else {
    Some(doc_comment)
  }
}

#[proc_macro_attribute]
pub fn typescript(args: TokenStream, input: TokenStream) -> TokenStream {
  let args = parse_macro_input!(args as AttributeArgs);
  let mut data_struct = parse_macro_input!(input as ItemStruct);

  // Extract attributes for the interface.
  // E.g. #[typescript(name = "IStruct")].
  let interface_args: InterfaceArguments = match InterfaceArguments::from_list(&args) {
    Ok(args) => args,
    Err(err) => {
      return TokenStream::from(err.write_errors());
    }
  };

  // Extract comment, name for interface.
  // Default to struct ident if unspecified.
  let interface_comment: String = extract_doc_comment(&data_struct.attrs)
    .map(|comment| format!("/** {comment} */\n"))
    .unwrap_or_default();
  let interface_name: String = if let Some(name) = interface_args.name {
    name
  } else {
    data_struct.ident.to_string()
  };
  let typescript_interface: String = format!("{interface_comment}interface {interface_name} {{\n");

  // Extract fields.
  let fields = match &mut data_struct.fields {
    Fields::Named(fields) => fields,
    _ => panic!("typescript attribute only supports structs with named fields"),
  };

  // Build TypeScript interface definition, extract attributes from fields.
  // E.g. #[typescript(optional, readonly, type = "string | bool")].
  let typescript_fields: String = match fields
    .named
    .iter_mut()
    .map(|field| {
      // Extract arguments.
      let field_args: FieldArguments = match FieldArguments::from_field(&field) {
        Ok(args) => args,
        Err(err) => {
          return Err(TokenStream::from(err.write_errors()));
        }
      };
      let doc_comment: String = extract_doc_comment(&field.attrs)
        .map(|comment| format!("  /** {comment} */\n"))
        .unwrap_or_default();
      let field_name: String = field_args
        .name
        .or_else(|| field.ident.as_ref().map(|ident| ident.to_string()))
        .expect("typescript attribute missing name and field has no identifier");
      let readonly: &str = match (field_args.readonly, interface_args.readonly.is_present()) {
        (Some(true), _) | (None, true) => "readonly ",
        _ => "",
      };
      let optional: &str = match (field_args.optional, interface_args.optional.is_present()) {
        (Some(true), _) | (None, true) => "?",
        _ => "",
      };
      let typescript_type: String = match field_args.ts_type {
        Some(ts_type) => ts_type,
        None => panic!("typescript field `{}` missing type", field_name),
      };

      // Strip `typescript` field attributes, otherwise throws "not a non-macro attribute" errors.
      field.attrs.retain(|attribute| {
        attribute
          .path
          .segments
          .first()
          .map(|path_segment| path_segment.ident.to_string())
          .unwrap_or_default()
          != "typescript"
      });

      Ok(format!(
        "{doc_comment}  {readonly}{field_name}{optional}: {typescript_type};\n"
      ))
    })
    .collect::<Result<String, TokenStream>>()
  {
    Ok(field_definitions) => field_definitions,
    Err(err) => return err,
  };

  // Arbitrary name, just needs to be semi-hygienic.
  let section_name: String = format!("___TYPESCRIPT_{}", interface_name);
  let section_token: syn::Ident = syn::Ident::new(&section_name, interface_name.span());

  // Convert the TypeScript definition string to use with quote.
  let typescript_definition: String = format!(r##"r#"{typescript_interface}{typescript_fields}}}"#;"##);
  let insert: proc_macro2::TokenStream = typescript_definition.parse().unwrap();

  // Preserve the input struct with the field attributes removed and
  // export the custom TypeScript interface definition via wasm-bindgen.
  TokenStream::from(quote! {
    #data_struct

    #[wasm_bindgen(typescript_custom_section)]
    const #section_token: &'static str = #insert
  })
}
