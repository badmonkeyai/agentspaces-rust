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

//! Field conditions on entries (SPEC §7.2): the Java matchers ([`Matcher`], Java `Matchers`),
//! the portable field filter grammar ([`FieldFilter`], [`parse_filter`], Java `FieldFilter`), and
//! a template's field and tag conditions together ([`Conditions`]), a port of `space.py`'s
//! matchers, `parse_filter`, `filter_compare`, and `Template.matches` / `matches_tags`, with the
//! Java classes as the authority wherever the clients differ.
//!
//! # The grammar
//!
//! One clause per string, `field op literal`, where `op` is `=`, `!=`, `<`, `<=`, `>`, `>=`, or
//! ` in ` (a comma-separated list): `priority>=3`, `topic != index`, `region in eu, us`. The
//! earliest operator in the clause is the operator, the longest at a tie, so `a<b<=c` compares
//! `a` with `b<=c` and `!=x` is malformed rather than the field `!`. A clause with no operator,
//! or none after its first character, is refused ([`FilterError`]); the golden vector
//! `filter_grammar_malformed` pins which.
//!
//! A clause judges a field's value by its string form ([`filter_form`], Java `String.valueOf`):
//! when the form and the literal both read as decimal numbers the comparison is numeric
//! (`3.0 = 3`, `1.0E7 > 9999999`), otherwise it is Java string order ([`filter_compare`]). A null
//! or absent value matches `!=` alone; `in` matches when any trimmed element equals the value.
//! The golden vector `filter_grammar_cases` pins the verdicts, which Java, Python, TypeScript,
//! and Ruby all give.
//!
//! # The matchers
//!
//! [`Matcher`] compares decoded values as Java `Matchers` compares boxed ones: numbers by value
//! whatever their encoding (`Int(3)` equals `Float(3.0)`; a double reads as the decimal
//! `Double.toString` prints), text by Java string order, booleans with `false` first, and
//! anything else not at all (an ordering matcher over a map is simply false, never an error).
//! NaN orders against nothing and equals nothing, as in IEEE 754, Python, and TypeScript (Java's
//! `Matchers.decimal` reads NaN as zero; this crate does not follow it there). Byte strings are
//! equal when their bytes are, as in Python (Java compares arrays by identity).
//!
//! # Where Java's own rules are followed
//!
//! - Trimming is `String.trim` (characters up to U+0020), digits are ASCII, a blank field name is
//!   refused by Java's `Character.isWhitespace`, and strings order by UTF-16 code units.
//! - A double's form is `Double.toString` ([`java_double_string`]): `1.0E7`, `1.0E-4`, `4.9E-324`.
//! - A decimal is read as `new BigDecimal(text)` reads it on JDK 25, so a literal whose scale
//!   falls outside a Java `int` or whose exponent has more than ten digits (`1e9999999999`,
//!   `1e-2147483648`) is not a number and compares as text.
//! - A byte string's Java form is `[B@` and an identity hash no other replica can reproduce; its
//!   form here is `[B@` alone, which orders against any literal not itself opening `[B@` as
//!   Java's does.
//!
//! Every judgment is total over its input and never panics.
#![warn(missing_docs)]

use std::cmp::Ordering;
use std::fmt::{self, Write as _};
use std::str::FromStr;

use crate::cbor::{Map, Value};
use crate::util::{java_order, non_null};

// ---------------------------------------------------------------------------------------------
// Matchers

/// A condition on one field's value, Java `Matchers` (SPEC §7.2). An absent field and a null one
/// are alike: both are Java's `null`.
///
/// - [`Matcher::Eq`] and [`Matcher::Ne`] compare numbers by value across [`Value::Int`] and
///   [`Value::Float`], and every other value by equality ([`Value`]'s `==`); `Eq(Value::Null)`
///   matches a null or absent field.
/// - The ordering matchers compare numbers by value, text in Java string order, and booleans
///   (`false < true`); a value of another kind than the bound, a null, and NaN never match.
/// - [`Matcher::In`] matches when any alternative is [`Matcher::Eq`] to the value.
/// - [`Matcher::Contains`] matches text containing the fragment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Matcher {
    /// Equal to the value.
    Eq(Value),
    /// Not equal to the value.
    Ne(Value),
    /// Strictly greater than the bound.
    Gt(Value),
    /// Greater than or equal to the bound.
    Gte(Value),
    /// Strictly less than the bound.
    Lt(Value),
    /// Less than or equal to the bound.
    Lte(Value),
    /// Equal to one of the alternatives.
    In(Vec<Value>),
    /// Text containing the fragment.
    Contains(String),
    /// Null or absent.
    IsNull,
    /// Present and not null.
    NotNull,
}

impl Matcher {
    /// Whether a field's value (`None` when the field is absent) satisfies this matcher.
    pub fn matches(&self, actual: Option<&Value>) -> bool {
        let actual = non_null(actual);
        match self {
            Matcher::Eq(expected) => same_value(actual, expected),
            Matcher::Ne(unexpected) => !same_value(actual, unexpected),
            Matcher::Gt(bound) => ordered(actual, bound).is_some_and(Ordering::is_gt),
            Matcher::Gte(bound) => ordered(actual, bound).is_some_and(Ordering::is_ge),
            Matcher::Lt(bound) => ordered(actual, bound).is_some_and(Ordering::is_lt),
            Matcher::Lte(bound) => ordered(actual, bound).is_some_and(Ordering::is_le),
            Matcher::In(alternatives) => alternatives
                .iter()
                .any(|alternative| same_value(actual, alternative)),
            Matcher::Contains(fragment) => actual
                .and_then(Value::as_str)
                .is_some_and(|text| text.contains(fragment.as_str())),
            Matcher::IsNull => actual.is_none(),
            Matcher::NotNull => actual.is_some(),
        }
    }
}

/// Java `Matchers.sameValue`: numbers by value, anything else by equality; `None` is null.
fn same_value(actual: Option<&Value>, expected: &Value) -> bool {
    let Some(actual) = actual else {
        return expected.is_null();
    };
    match (Number::of(actual), Number::of(expected)) {
        (Some(a), Some(b)) => a.compare(b) == Some(Ordering::Equal),
        _ => actual == expected,
    }
}

/// Java `Matchers.comparing`: numbers by value, text and booleans by their natural order, and no
/// order for anything else (a null, a NaN, or a value of another kind than the bound).
fn ordered(actual: Option<&Value>, bound: &Value) -> Option<Ordering> {
    let actual = actual?;
    if let (Some(a), Some(b)) = (Number::of(actual), Number::of(bound)) {
        return a.compare(b);
    }
    match (actual, bound) {
        (Value::Text(a), Value::Text(b)) => Some(java_order(a, b)),
        (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

/// A number as Java `Matchers.decimal` compares it.
#[derive(Clone, Copy)]
enum Number {
    Int(i128),
    Float(f64),
}

impl Number {
    fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Int(n) => Some(Number::Int(*n)),
            Value::Float(x) => Some(Number::Float(*x)),
            _ => None,
        }
    }

    /// The order of two numbers by value, `None` when either is NaN. A double is the decimal
    /// `Double.toString` prints (Java `BigDecimal.valueOf(double)`); an infinity lies beyond
    /// every integer, which CBOR bounds to 2^64.
    fn compare(self, other: Self) -> Option<Ordering> {
        match (self, other) {
            (Number::Int(a), Number::Int(b)) => Some(a.cmp(&b)),
            (Number::Float(a), Number::Float(b)) => a.partial_cmp(&b),
            (Number::Int(a), Number::Float(b)) => int_float(a, b),
            (Number::Float(a), Number::Int(b)) => int_float(b, a).map(Ordering::reverse),
        }
    }
}

/// The order of an integer against a double.
fn int_float(int: i128, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        None
    } else if float.is_infinite() {
        Some(if float > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        })
    } else {
        let a = Decimal::parse(&int.to_string())?;
        let b = Decimal::parse(&java_double_string(float))?;
        Some(a.cmp(&b))
    }
}

// ---------------------------------------------------------------------------------------------
// The portable grammar

/// The operators as they appear in a clause; ` in ` needs its spaces.
const OPERATORS: [&str; 7] = ["!=", "<=", ">=", "=", "<", ">", " in "];

/// A clause's operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterOp {
    /// `=`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Lte,
    /// `>`
    Gt,
    /// `>=`
    Gte,
    /// `in`, over a comma-separated list.
    In,
}

impl FilterOp {
    /// The operator as Java's `FieldFilter.op` names it (`"="`, ..., `"in"`).
    pub fn as_str(self) -> &'static str {
        match self {
            FilterOp::Eq => "=",
            FilterOp::Ne => "!=",
            FilterOp::Lt => "<",
            FilterOp::Lte => "<=",
            FilterOp::Gt => ">",
            FilterOp::Gte => ">=",
            FilterOp::In => "in",
        }
    }

    fn of(operator: &str) -> Option<Self> {
        Some(match operator {
            "=" => FilterOp::Eq,
            "!=" => FilterOp::Ne,
            "<" => FilterOp::Lt,
            "<=" => FilterOp::Lte,
            ">" => FilterOp::Gt,
            ">=" => FilterOp::Gte,
            " in " => FilterOp::In,
            _ => return None,
        })
    }
}

/// Why a clause was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    /// No operator, or none after the clause's first character. Carries the clause.
    #[error(
        "malformed field filter '{0}'; use \"field=value\", \"field!=value\", \"field<value\", \
         \"field<=value\", \"field>value\", \"field>=value\", or \"field in a,b,c\""
    )]
    Malformed(String),
    /// The text before the operator is blank (Java `String.isBlank`). Carries the clause.
    #[error("a field filter needs a field name: '{0}'")]
    BlankField(String),
}

/// One clause of the portable field filter grammar (Java `FieldFilter`): a field, an operator,
/// and the literal text (for `in`, the comma-separated list). Built by [`parse_filter`]; its
/// [`Display`](fmt::Display) form is Java's `toString`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldFilter {
    field: String,
    op: FilterOp,
    literal: String,
}

/// Parses one clause, `field op literal` with spaces around the operator allowed, or
/// `field in a,b,c` (Java `FieldFilter.parse`). The clause, the field, and the literal are
/// trimmed as Java trims; the literal may be empty (`topic=` matches the empty string).
pub fn parse_filter(clause: &str) -> Result<FieldFilter, FilterError> {
    let text = java_trim(clause);
    // The earliest operator in the clause is the operator; at a tie the longest (so "<=" beats
    // "<"), and "!=x" is malformed rather than the field "!".
    let mut best: Option<(usize, &str)> = None;
    for operator in OPERATORS {
        if let Some(at) = text.find(operator) {
            let better = best.is_none_or(|(best_at, best_operator)| {
                at < best_at || (at == best_at && operator.len() > best_operator.len())
            });
            if better {
                best = Some((at, operator));
            }
        }
    }
    let malformed = || FilterError::Malformed(clause.to_owned());
    let (at, operator) = best.filter(|&(at, _)| at > 0).ok_or_else(malformed)?;
    // The operators are ASCII and `find` answers a character boundary, so both slices exist.
    let field = text.get(..at).map(java_trim).ok_or_else(malformed)?;
    let literal = text
        .get(at + operator.len()..)
        .map(java_trim)
        .ok_or_else(malformed)?;
    let op = FilterOp::of(operator).ok_or_else(malformed)?;
    if field.chars().all(java_whitespace) {
        return Err(FilterError::BlankField(clause.to_owned()));
    }
    Ok(FieldFilter {
        field: field.to_owned(),
        op,
        literal: literal.to_owned(),
    })
}

impl FieldFilter {
    /// The field the clause judges.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The operator.
    pub fn op(&self) -> FilterOp {
        self.op
    }

    /// The literal text; for [`FilterOp::In`], the comma-separated list.
    pub fn literal(&self) -> &str {
        &self.literal
    }

    /// Whether a value satisfies this clause (Java `FieldFilter.matches`): [`Value::Null`] (a
    /// null or absent field) matches `!=` alone; otherwise the value's [`filter_form`] is
    /// compared with the literal by [`filter_compare`], and `in` matches when the form equals
    /// any trimmed element of the list (an empty element included).
    pub fn test(&self, value: &Value) -> bool {
        if value.is_null() {
            return self.op == FilterOp::Ne;
        }
        let form = filter_form(value);
        let compared = || filter_compare(&form, &self.literal);
        match self.op {
            FilterOp::Eq => compared().is_eq(),
            FilterOp::Ne => compared().is_ne(),
            FilterOp::Lt => compared().is_lt(),
            FilterOp::Lte => compared().is_le(),
            FilterOp::Gt => compared().is_gt(),
            FilterOp::Gte => compared().is_ge(),
            FilterOp::In => self
                .literal
                .split(',')
                .any(|element| filter_compare(&form, java_trim(element)).is_eq()),
        }
    }
}

/// `field op literal`, ` in ` spelled with its spaces (Java `FieldFilter.toString`).
impl fmt::Display for FieldFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = match self.op {
            FilterOp::In => " in ",
            op => op.as_str(),
        };
        write!(f, "{}{op}{}", self.field, self.literal)
    }
}

/// [`parse_filter`].
impl FromStr for FieldFilter {
    type Err = FilterError;

    fn from_str(clause: &str) -> Result<Self, Self::Err> {
        parse_filter(clause)
    }
}

/// Java `FieldFilter.compare`: numeric when the trimmed form and the trimmed literal both read
/// as decimal numbers (`[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?` with ASCII digits, as Java
/// `BigDecimal` reads it), otherwise the untrimmed strings in Java string order.
pub fn filter_compare(form: &str, literal: &str) -> Ordering {
    match (
        Decimal::parse(java_trim(form)),
        Decimal::parse(java_trim(literal)),
    ) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => java_order(form, literal),
    }
}

/// The string form a clause judges a value by, Java's `String.valueOf` of the decoded value:
/// text as it is, `true` / `false`, an integer in decimal (a bignum too), a decimal as Java's
/// `BigDecimal.toString` prints it, a double as [`java_double_string`] prints it, `null`, an array as `[a, b]` and a map as `{k=v, k2=v2}` (Java's `List` and
/// `Map` forms, elements recursively), and a byte string as `[B@` (see the module notes).
pub fn filter_form(value: &Value) -> String {
    let mut out = String::new();
    write_form(value, &mut out);
    out
}

fn write_form(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        // Java's BigInteger.toString and BigDecimal.toString.
        Value::BigInt(big) => {
            let _ = write!(out, "{big}");
        }
        Value::Decimal(decimal) => {
            let _ = write!(out, "{decimal}");
        }
        Value::Float(x) => out.push_str(&java_double_string(*x)),
        Value::Bytes(_) => out.push_str("[B@"),
        Value::Text(text) => out.push_str(text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_form(item, out);
            }
            out.push(']');
        }
        Value::Map(map) => write_map_form(map, out),
    }
}

fn write_map_form(map: &Map, out: &mut String) {
    out.push('{');
    for (index, (key, item)) in map.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write_form(key, out);
        out.push('=');
        write_form(item, out);
    }
    out.push('}');
}

// ---------------------------------------------------------------------------------------------
// Conditions

/// One condition on a field: a [`Matcher`], or a clause of the portable grammar.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Condition {
    /// A Java matcher.
    Matcher(Matcher),
    /// A clause of the portable grammar.
    Filter(FieldFilter),
}

impl Condition {
    /// Whether a field's value (`None` when the field is absent) satisfies this condition.
    pub fn matches(&self, actual: Option<&Value>) -> bool {
        match self {
            Condition::Matcher(matcher) => matcher.matches(actual),
            Condition::Filter(filter) => filter.test(actual.unwrap_or(&Value::Null)),
        }
    }
}

/// A template's conditions (`space.py`'s `Template` without the entry type): conditions on
/// payload fields and matchers on tags, all of which must hold. Several conditions may name one
/// field; each must hold.
///
/// ```
/// use agentspaces_wire::cbor::Map;
/// use agentspaces_wire::filters::{Conditions, Matcher};
///
/// let conditions = Conditions::new()
///     .with_field("topic", Matcher::Eq("index".into()))
///     .with_clause("priority>=3")?
///     .with_tag("region", Matcher::In(vec!["eu".into(), "us".into()]));
/// let payload: Map = [("topic", "index".into()), ("priority", agentspaces_wire::cbor::Value::Int(5))]
///     .into_iter()
///     .collect();
/// let tags: Map = [("region", "eu")].into_iter().collect();
/// assert!(conditions.matches(&payload, &tags));
/// assert!(!conditions.matches_tags(&Map::new()));
/// # Ok::<(), agentspaces_wire::filters::FilterError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Conditions {
    fields: Vec<(String, Condition)>,
    tags: Vec<(String, Matcher)>,
}

impl Conditions {
    /// No conditions: everything matches.
    pub fn new() -> Self {
        Self::default()
    }

    /// These conditions and a matcher on a payload field.
    pub fn with_field(mut self, field: impl Into<String>, matcher: Matcher) -> Self {
        self.fields
            .push((field.into(), Condition::Matcher(matcher)));
        self
    }

    /// These conditions and a clause of the portable grammar on its field.
    pub fn with_filter(mut self, filter: FieldFilter) -> Self {
        self.fields
            .push((filter.field.clone(), Condition::Filter(filter)));
        self
    }

    /// These conditions and a clause parsed by [`parse_filter`], or the clause's refusal.
    pub fn with_clause(self, clause: &str) -> Result<Self, FilterError> {
        Ok(self.with_filter(parse_filter(clause)?))
    }

    /// These conditions and a matcher on a tag.
    pub fn with_tag(mut self, key: impl Into<String>, matcher: Matcher) -> Self {
        self.tags.push((key.into(), matcher));
        self
    }

    /// The field conditions, in the order they were added.
    pub fn field_conditions(&self) -> &[(String, Condition)] {
        &self.fields
    }

    /// The tag matchers, in the order they were added.
    pub fn tag_conditions(&self) -> &[(String, Matcher)] {
        &self.tags
    }

    /// Whether there are no conditions at all.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.tags.is_empty()
    }

    /// Whether a decoded payload and its tags meet every condition (`Template.matches`): each
    /// field condition holds for the payload's field (absent reads as null), and
    /// [`Conditions::matches_tags`] holds.
    pub fn matches(&self, payload: &Map, tags: &Map) -> bool {
        self.fields
            .iter()
            .all(|(field, condition)| condition.matches(payload.get(field)))
            && self.matches_tags(tags)
    }

    /// Whether tags meet every tag matcher (`Template.matches_tags`); an absent tag reads as
    /// null.
    pub fn matches_tags(&self, tags: &Map) -> bool {
        self.tags
            .iter()
            .all(|(key, matcher)| matcher.matches(tags.get(key)))
    }
}

// ---------------------------------------------------------------------------------------------
// Java's text rules

/// Java `String.trim`: every character up to U+0020 off both ends.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// Java `Character.isWhitespace`: the space separators but the no-break ones, the line and
/// paragraph separators, the ASCII controls `\t` to `\r`, and U+001C to U+001F.
pub(crate) fn java_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1C}'..='\u{20}'
            | '\u{1680}'
            | '\u{2000}'..='\u{2006}'
            | '\u{2008}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// Java `Double.toString` (JDK 19 and later): `NaN`, `Infinity`, `-Infinity`, `0.0`, `-0.0`;
/// otherwise the shortest decimal that reads back as the same double (two digits where one would
/// do but two are closer, so the smallest subnormal is `4.9E-324`), written plain with at least
/// one fraction digit from 10^-3 up to 10^7 (`0.001`, `9999999.0`) and in computerized
/// scientific notation outside it (`1.0E-4`, `1.0E7`, `1.7976931348623157E308`).
///
/// The form a double compares under in the filter grammar, and the decimal the matchers read a
/// double as.
pub fn java_double_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_owned();
    }
    let (digits, exponent) = java_digits(value.abs());
    let mut out = String::with_capacity(digits.len() + 8);
    if value.is_sign_negative() {
        out.push('-');
    }
    match usize::try_from(exponent) {
        // 10^0 up to 10^7: the integer digits, a point, then the rest or a zero.
        Ok(whole) if exponent < 7 => {
            let whole = whole + 1;
            match (digits.get(..whole), digits.get(whole..)) {
                (Some(integer), Some(fraction)) if !fraction.is_empty() => {
                    out.push_str(integer);
                    out.push('.');
                    out.push_str(fraction);
                }
                _ => {
                    out.push_str(&digits);
                    out.extend(std::iter::repeat_n('0', whole.saturating_sub(digits.len())));
                    out.push_str(".0");
                }
            }
        }
        // 10^-3 up to 10^0: "0.", the leading zeros, the digits.
        Err(_) if exponent >= -3 => {
            out.push_str("0.");
            let zeros = usize::try_from(-1 - exponent).unwrap_or_default();
            out.extend(std::iter::repeat_n('0', zeros));
            out.push_str(&digits);
        }
        _ => {
            let (first, rest) = digits.split_at_checked(1).unwrap_or((&digits, ""));
            out.push_str(first);
            out.push('.');
            out.push_str(if rest.is_empty() { "0" } else { rest });
            let _ = write!(out, "E{exponent}");
        }
    }
    out
}

/// The significant digits and the decimal exponent of the first one that Java's
/// `Double.toString` prints for a positive finite double.
///
/// Java takes, among the decimals of the shortest length that read back as the double (of one or
/// two digits when one would do), the one closest to its exact value, the one with the even last
/// digit at a tie. Rust's `{:.N e}` rounds the exact value to that length half to even, so it is
/// Java's decimal whenever it still reads back as the same double; when it does not, the closest
/// decimal that does lies on the other side, and that is Rust's shortest form.
fn java_digits(value: f64) -> (String, i32) {
    let (shortest, exponent) = scientific(&format!("{value:e}"));
    let rounded = format!("{value:.*e}", shortest.len().max(2) - 1);
    if rounded.parse::<f64>() == Ok(value) {
        let (mut digits, exponent) = scientific(&rounded);
        // Only a two-digit choice for a one-digit decimal can end in a zero ("1.0e7").
        while digits.len() > 1 && digits.ends_with('0') {
            digits.pop();
        }
        return (digits, exponent);
    }
    (shortest, exponent)
}

/// The digits and the exponent of Rust's `{:e}` form (`1.5e-5`, `1e7`).
fn scientific(text: &str) -> (String, i32) {
    let (mantissa, exponent) = text.split_once('e').unwrap_or((text, "0"));
    let digits = mantissa.chars().filter(char::is_ascii_digit).collect();
    (digits, exponent.parse().unwrap_or_default())
}

// ---------------------------------------------------------------------------------------------
// Decimals

/// A decimal number as Java `BigDecimal` holds one for comparison: its sign and its significant
/// digits (no leading or trailing zeros; none for zero) times ten to `exponent`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decimal {
    negative: bool,
    digits: Vec<u8>,
    exponent: i64,
}

impl Decimal {
    /// The decimal of `[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?` (ASCII digits, the whole text), as
    /// `new BigDecimal(text)` reads it on the JDK 25 the reference nodes run: `None` for any
    /// other text, for an exponent of more than ten digits after its leading zeros, and for a
    /// scale (the fraction's digits less the exponent) outside a Java `int`, where Java throws
    /// `NumberFormatException`. (JDK 21 also refuses an exponent outside an `int`, which differs
    /// only for exponents beyond 2^31 whose scale still fits.)
    fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let mut at = 0;
        let negative = match bytes.first() {
            Some(b'-') => {
                at = 1;
                true
            }
            Some(b'+') => {
                at = 1;
                false
            }
            _ => false,
        };
        let digits_from = |at: usize| {
            bytes.get(at..).map_or(0, |rest| {
                rest.iter().take_while(|b| b.is_ascii_digit()).count()
            })
        };
        let integer = bytes.get(at..at + digits_from(at))?;
        at += integer.len();
        let mut fraction: &[u8] = &[];
        if bytes.get(at) == Some(&b'.') {
            at += 1;
            fraction = bytes.get(at..at + digits_from(at))?;
            at += fraction.len();
        }
        if integer.is_empty() && fraction.is_empty() {
            return None;
        }
        let mut exponent: i64 = 0;
        if matches!(bytes.get(at), Some(b'e' | b'E')) {
            at += 1;
            let exponent_negative = match bytes.get(at) {
                Some(b'-') => {
                    at += 1;
                    true
                }
                Some(b'+') => {
                    at += 1;
                    false
                }
                _ => false,
            };
            let written = bytes.get(at..at + digits_from(at))?;
            if written.is_empty() {
                return None;
            }
            at += written.len();
            // Leading zeros aside, Java takes at most ten exponent digits.
            let significant = written
                .iter()
                .position(|&b| b != b'0')
                .map_or(&[][..], |first| written.get(first..).unwrap_or_default());
            if significant.len() > 10 {
                return None;
            }
            let magnitude = significant
                .iter()
                .fold(0i64, |sum, &b| sum * 10 + i64::from(b - b'0'));
            exponent = if exponent_negative {
                -magnitude
            } else {
                magnitude
            };
        }
        if at != bytes.len() {
            return None;
        }
        // Java's scale is the fraction's length less the exponent, and must be an int too.
        let scale = i64::try_from(fraction.len()).ok()? - exponent;
        i32::try_from(scale).ok()?;
        let mut digits: Vec<u8> = integer
            .iter()
            .chain(fraction)
            .map(|b| b - b'0')
            .skip_while(|&d| d == 0)
            .collect();
        let trailing = digits.iter().rev().take_while(|&&d| d == 0).count();
        digits.truncate(digits.len() - trailing);
        let exponent = i64::try_from(trailing).ok()? - scale;
        Some(Self {
            negative: negative && !digits.is_empty(),
            digits,
            exponent,
        })
    }

    /// -1, 0, or 1.
    fn signum(&self) -> i8 {
        match (self.digits.is_empty(), self.negative) {
            (true, _) => 0,
            (false, true) => -1,
            (false, false) => 1,
        }
    }

    /// The power of ten of the leading digit.
    fn magnitude(&self) -> i64 {
        self.exponent + i64::try_from(self.digits.len()).unwrap_or(i64::MAX) - 1
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        let sign = self.signum().cmp(&other.signum());
        if sign.is_ne() || self.signum() == 0 {
            return sign;
        }
        let by_size = self
            .magnitude()
            .cmp(&other.magnitude())
            .then_with(|| self.digits.cmp(&other.digits));
        if self.negative {
            by_size.reverse()
        } else {
            by_size
        }
    }
}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decimal(text: &str) -> Option<Decimal> {
        Decimal::parse(text)
    }

    #[test]
    fn decimals_read_as_big_decimal_reads_them() {
        let cmp = |a: &str, b: &str| decimal(a).unwrap().cmp(&decimal(b).unwrap());
        assert_eq!(cmp("3", "3.0"), Ordering::Equal);
        assert_eq!(cmp("-0", "0.000"), Ordering::Equal);
        assert_eq!(cmp(".5", "0.50e0"), Ordering::Equal);
        assert_eq!(cmp("1e7", "9999999"), Ordering::Greater);
        assert_eq!(cmp("-2", "-10"), Ordering::Greater);
        assert_eq!(cmp("12", "123e-1"), Ordering::Less);
        assert_eq!(cmp("1.", "1"), Ordering::Equal);
        assert_eq!(cmp("+7", "7"), Ordering::Equal);
        assert_eq!(cmp("1e0000000000002", "100"), Ordering::Equal);
        assert_eq!(cmp("1e2147483647", "1e2147483646"), Ordering::Greater);
        assert_eq!(cmp("1.5e2147483649", "15e2147483648"), Ordering::Equal);
        assert_eq!(
            cmp("1e00000000002147483647", "1e2147483647"),
            Ordering::Equal
        );
        // JDK 25: the scale (fraction digits less the exponent) must be an int, and the exponent
        // at most ten digits after its leading zeros.
        for not_a_number in [
            "",
            "+",
            "-",
            ".",
            "e5",
            "1e",
            "1e+",
            "1.2.3",
            "1 ",
            " 1",
            "0x1",
            "\u{661}",
            "1e-2147483648",
            "0e-2147483648",
            "1e2147483649",
            "1e9999999999",
            "1e99999999999",
            "0e99999999999",
            "0.1e-2147483647",
        ] {
            assert_eq!(decimal(not_a_number), None, "{not_a_number:?}");
        }
        for number in [
            "1e2147483648",
            "1e-2147483647",
            ".1e-2147483646",
            "0e2147483648",
        ] {
            assert!(decimal(number).is_some(), "{number}");
        }
    }

    #[test]
    fn java_whitespace_and_trim() {
        assert_eq!(java_trim("\u{0}\t x \u{1F}"), "x");
        assert_eq!(java_trim("\u{A0}x"), "\u{A0}x");
        assert!(java_whitespace('\u{2003}') && java_whitespace('\u{1C}'));
        assert!(!java_whitespace('\u{A0}') && !java_whitespace('\u{2007}'));
        assert!(!java_whitespace('\u{202F}') && !java_whitespace('\u{85}'));
    }
}
