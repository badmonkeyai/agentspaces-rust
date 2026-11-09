// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `#[derive(Entry)]` for AgentSpaces for Rust: binds a type to the schema name the fleet knows
//! it by, implementing `agentspaces::entry::Entry`.
//!
//! Use it through the `agentspaces` crate, which re-exports it, beside serde's derives:
//!
//! ```
//! use agentspaces::Entry;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, Entry)]
//! #[entry(schema = "shop.Order#v1")]
//! struct Order {
//!     item: String,
//!     quantity: u32,
//! }
//! ```
//!
//! The attribute is required and takes:
//!
//! - `schema = "..."`, required: the wire schema name, a non-empty string literal without
//!   whitespace or control characters, such as `"shop.Order#v1"` or a Java record's
//!   `"com.acme.Seed$Task#v1"`.
//! - `crate = "..."`, optional: the path of the `agentspaces` crate, for a crate that renames
//!   the dependency (`crate = "aspace"`) or for code inside `agentspaces` itself
//!   (`crate = "crate"`). The default is `::agentspaces`.
//!
//! A missing, repeated, or malformed attribute is a compile error that says what to write.
//! The type must also implement `Serialize` and `DeserializeOwned` and be `Send + Sync +
//! 'static`, the supertraits of `Entry`. A generic type's impl is bounded by exactly that
//! (`where Self: Serialize + DeserializeOwned + Send + Sync + 'static`), so `Batch<T>` is an
//! entry for every `T` that makes it serializable.

#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::meta::ParseNestedMeta;
use syn::{Data, DeriveInput, Error, Expr, ExprLit, Lit, LitStr, Meta, Path, parse_macro_input};

/// What a correct attribute looks like, for error messages.
const USAGE: &str = "write #[entry(schema = \"shop.Order#v1\")]";

/// Implements `agentspaces::entry::Entry` with the schema name of `#[entry(schema = "...")]`.
#[proc_macro_derive(Entry, attributes(entry))]
pub fn derive_entry(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// The parsed `#[entry(...)]` attribute.
struct Options {
    schema: LitStr,
    krate: Path,
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    if let Data::Union(union) = &input.data {
        return Err(Error::new(
            union.union_token.span,
            "Entry cannot be derived for a union; serde cannot serialize one",
        ));
    }
    let Options { schema, krate } = options(input)?;
    let name = &input.ident;
    // A generic type is an entry for the arguments that make it one, so the impl asks for the
    // supertraits of `Entry` rather than for bounds on each parameter.
    let mut generics = input.generics.clone();
    if !generics.params.is_empty() {
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote! {
                Self: #krate::entry::serde::Serialize
                    + #krate::entry::serde::de::DeserializeOwned
                    + ::core::marker::Send
                    + ::core::marker::Sync
                    + 'static
            });
    }
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #krate::entry::Entry for #name #type_generics #where_clause {
            const SCHEMA: &'static str = #schema;
        }
    })
}

/// Reads the one `#[entry(...)]` attribute of the type.
fn options(input: &DeriveInput) -> syn::Result<Options> {
    let mut found = None;
    for attr in input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("entry"))
    {
        if found.is_some() {
            return Err(Error::new_spanned(
                attr,
                format!("more than one #[entry] attribute; {USAGE} once"),
            ));
        }
        found = Some(attr);
    }
    let Some(attr) = found else {
        return Err(Error::new(
            Span::call_site(),
            format!(
                "#[derive(Entry)] needs the schema name the fleet knows `{}` by; {USAGE}",
                input.ident
            ),
        ));
    };

    if !matches!(attr.meta, Meta::List(_)) {
        return Err(Error::new_spanned(
            attr,
            format!("#[entry] takes its keys in parentheses; {USAGE}"),
        ));
    }
    let mut schema: Option<LitStr> = None;
    let mut krate: Option<Path> = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("schema") {
            if schema.is_some() {
                return Err(meta.error("`schema` is given twice"));
            }
            let literal = string_literal(&meta, "schema", USAGE)?;
            check_schema(&literal)?;
            schema = Some(literal);
            Ok(())
        } else if meta.path.is_ident("crate") {
            if krate.is_some() {
                return Err(meta.error("`crate` is given twice"));
            }
            let usage = "write crate = \"agentspaces\"";
            let literal = string_literal(&meta, "crate", usage)?;
            krate = Some(literal.parse().map_err(|error| {
                Error::new(
                    literal.span(),
                    format!("`crate` must be a path; {usage}: {error}"),
                )
            })?);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown #[entry] key; the keys are `schema` and `crate`: {USAGE}"
            )))
        }
    })?;

    let Some(schema) = schema else {
        return Err(Error::new_spanned(
            attr,
            format!("#[entry] is missing the schema name; {USAGE}"),
        ));
    };
    let krate = match krate {
        Some(path) => path,
        None => syn::parse_quote!(::agentspaces),
    };
    Ok(Options { schema, krate })
}

/// The string literal of `key = "..."`, or an error showing `usage`.
fn string_literal(meta: &ParseNestedMeta<'_>, key: &str, usage: &str) -> syn::Result<LitStr> {
    let message = format!("`{key}` takes a string literal; {usage}");
    let value = meta
        .value()
        .map_err(|_| Error::new_spanned(&meta.path, &message))?;
    match value.parse::<Expr>() {
        Ok(Expr::Lit(ExprLit {
            lit: Lit::Str(literal),
            ..
        })) => Ok(literal),
        Ok(other) => Err(Error::new_spanned(other, message)),
        Err(error) => Err(Error::new(error.span(), message)),
    }
}

/// Refuses a schema name the wire cannot carry usefully: empty, or with whitespace or control
/// characters.
fn check_schema(literal: &LitStr) -> syn::Result<()> {
    let schema = literal.value();
    if schema.is_empty() {
        return Err(Error::new(
            literal.span(),
            format!("the schema name is empty; {USAGE}"),
        ));
    }
    if let Some(c) = schema.chars().find(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::new(
            literal.span(),
            format!(
                "the schema name {schema:?} contains {c:?}; a schema name has no whitespace or \
                 control characters"
            ),
        ));
    }
    Ok(())
}
