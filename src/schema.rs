//! The strict argument schema (L1, F-13): the subset of JSON Schema a lockfile pins beside each
//! tool's upstream definition, to check the arguments of every call in `G_canon`.
//!
//! The upstream `inputSchema` is pinned whole for drift, but it is the tool's own text and may
//! use any keyword. Enforcement uses this second schema instead, which the lockfile's reviewers
//! write, and which allows only `type`, `properties`, `required`, `additionalProperties: false`,
//! `enum` and length and range limits:
//!
//! - every node has exactly one `type`;
//! - an object node either lists its `properties`, and then must say
//!   `"additionalProperties": false`, or lists neither: it is then a leaf that takes any object,
//!   which only a free `data` or `store_write` argument may be;
//! - `required` names listed properties; `enum` lists distinct scalars of the node's type;
//! - `minLength` and `maxLength` go on strings (counted in code points), `minimum` and `maximum`
//!   on integers (safe integers only), `minItems` and `maxItems` on arrays.
//!
//! Any other keyword, a `type` array, an `additionalProperties` that is not `false`, or a
//! fractional bound is refused, so the schema means the same to every reader. There is no
//! `items`: arrays are checked by count only, and a declared argument never sits inside one.

use std::collections::{BTreeMap, BTreeSet};

use crate::jcs::{self, JcsValue, MAX_SAFE_INTEGER};

/// Deepest a schema may nest, counting the root as 1.
pub const MAX_SCHEMA_DEPTH: usize = 16;
/// Most nodes one schema may hold.
pub const MAX_SCHEMA_NODES: usize = 1024;

/// Why a schema was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// A node is not an object.
    #[error("a schema node must be an object")]
    NotObject,
    /// A keyword outside the strict subset.
    #[error("keyword not allowed in a strict schema")]
    UnknownKeyword,
    /// `type` is missing, not a string, or not a JSON Schema type.
    #[error("each node needs one type")]
    BadType,
    /// A keyword that does not apply to the node's type.
    #[error("keyword does not apply to this type")]
    WrongTypeForKeyword,
    /// `properties` without `"additionalProperties": false`, or the reverse.
    #[error("an object with properties must set additionalProperties to false")]
    OpenObject,
    /// `required` is not an array of distinct names of listed properties.
    #[error("required must list distinct properties")]
    BadRequired,
    /// `enum` is not a non-empty array of distinct scalars of the node's type.
    #[error("enum must list distinct scalars of the node's type")]
    BadEnum,
    /// A bound is not a non-negative or safe integer, or a lower bound exceeds its upper bound.
    #[error("bounds must be integers, with the lower at most the upper")]
    BadBound,
    /// The root is not an object with properties.
    #[error("the root must be an object with properties")]
    BadRoot,
    /// Deeper than [`MAX_SCHEMA_DEPTH`] or larger than [`MAX_SCHEMA_NODES`].
    #[error("schema too large")]
    TooLarge,
}

/// The JSON type a node accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaType {
    /// An object.
    Object,
    /// An array.
    Array,
    /// A string.
    String,
    /// A number that is a safe integer.
    Integer,
    /// Any number.
    Number,
    /// `true` or `false`.
    Boolean,
    /// `null`.
    Null,
}

impl SchemaType {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "object" => Self::Object,
            "array" => Self::Array,
            "string" => Self::String,
            "integer" => Self::Integer,
            "number" => Self::Number,
            "boolean" => Self::Boolean,
            "null" => Self::Null,
            _ => return None,
        })
    }

    fn admits(self, value: &JcsValue) -> bool {
        match (self, value) {
            (Self::Object, JcsValue::Object(_))
            | (Self::Array, JcsValue::Array(_))
            | (Self::String, JcsValue::String(_))
            | (Self::Number, JcsValue::Number(_))
            | (Self::Boolean, JcsValue::Bool(_))
            | (Self::Null, JcsValue::Null) => true,
            (Self::Integer, JcsValue::Number(number)) => number.as_i64().is_some(),
            _ => false,
        }
    }
}

/// One node of a strict schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaNode {
    /// The type it accepts.
    pub kind: SchemaType,
    /// For a closed object, its members by name; `None` for any other node, including an
    /// object leaf, which takes any object.
    pub properties: Option<BTreeMap<String, SchemaNode>>,
    /// The members a closed object must have.
    pub required: BTreeSet<String>,
    /// The values allowed, if limited.
    pub allowed: Option<Vec<JcsValue>>,
    /// Fewest code points in a string.
    pub min_length: Option<u64>,
    /// Most code points in a string.
    pub max_length: Option<u64>,
    /// Smallest integer.
    pub minimum: Option<i64>,
    /// Largest integer.
    pub maximum: Option<i64>,
    /// Fewest items in an array.
    pub min_items: Option<u64>,
    /// Most items in an array.
    pub max_items: Option<u64>,
}

impl SchemaNode {
    /// Whether `value` satisfies this node.
    #[must_use]
    pub fn accepts(&self, value: &JcsValue) -> bool {
        if !self.kind.admits(value) {
            return false;
        }
        if let Some(allowed) = &self.allowed
            && !allowed.contains(value)
        {
            return false;
        }
        match value {
            JcsValue::String(text) => {
                let length = u64::try_from(text.as_str().chars().count()).unwrap_or(u64::MAX);
                within(length, self.min_length, self.max_length)
            }
            JcsValue::Number(number) => number.as_i64().is_none_or(|integer| {
                self.minimum.is_none_or(|minimum| integer >= minimum)
                    && self.maximum.is_none_or(|maximum| integer <= maximum)
            }),
            JcsValue::Array(items) => within(
                u64::try_from(items.len()).unwrap_or(u64::MAX),
                self.min_items,
                self.max_items,
            ),
            JcsValue::Object(object) => {
                let Some(properties) = &self.properties else {
                    // An object leaf takes any object.
                    return true;
                };
                self.required.iter().all(|name| object.contains_key(name))
                    && object.entries().iter().all(|(key, child)| {
                        properties
                            .get(key.as_str())
                            .is_some_and(|node| node.accepts(child))
                    })
            }
            JcsValue::Null | JcsValue::Bool(_) => true,
        }
    }
}

fn within(count: u64, min: Option<u64>, max: Option<u64>) -> bool {
    min.is_none_or(|min| count >= min) && max.is_none_or(|max| count <= max)
}

/// A tool's strict argument schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSchema {
    root: SchemaNode,
}

/// One leaf of a schema: a node that is not a closed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaLeaf<'a> {
    /// Its RFC 6901 pointer into `arguments`, with each name escaped.
    pub pointer: String,
    /// The node.
    pub node: &'a SchemaNode,
    /// Whether it and every object on its path are required, so a valid call always has it.
    pub always_present: bool,
}

impl ArgSchema {
    /// Parses a strict schema.
    ///
    /// # Errors
    ///
    /// Returns the first [`SchemaError`] found.
    pub fn parse(value: &JcsValue) -> Result<Self, SchemaError> {
        let mut budget = MAX_SCHEMA_NODES;
        let root = node(value, 1, &mut budget)?;
        if root.kind != SchemaType::Object || root.properties.is_none() {
            return Err(SchemaError::BadRoot);
        }
        Ok(Self { root })
    }

    /// Whether `arguments` satisfies the schema.
    #[must_use]
    pub fn accepts(&self, arguments: &JcsValue) -> bool {
        self.root.accepts(arguments)
    }

    /// Every leaf, in pointer order.
    #[must_use]
    pub fn leaves(&self) -> Vec<SchemaLeaf<'_>> {
        let mut leaves = Vec::new();
        collect(&self.root, String::new(), true, &mut leaves);
        leaves
    }
}

fn collect<'a>(node: &'a SchemaNode, at: String, present: bool, out: &mut Vec<SchemaLeaf<'a>>) {
    match &node.properties {
        Some(properties) => {
            for (name, child) in properties {
                let pointer = format!("{at}/{}", jcs::escape_pointer_token(name));
                collect(child, pointer, present && node.required.contains(name), out);
            }
        }
        None => out.push(SchemaLeaf {
            pointer: at,
            node,
            always_present: present,
        }),
    }
}

const KEYWORDS: [&str; 11] = [
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
];

fn node(value: &JcsValue, depth: usize, budget: &mut usize) -> Result<SchemaNode, SchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaError::TooLarge);
    }
    *budget = budget.checked_sub(1).ok_or(SchemaError::TooLarge)?;
    let object = value.as_object().ok_or(SchemaError::NotObject)?;
    if object
        .entries()
        .iter()
        .any(|(key, _)| !KEYWORDS.contains(&key.as_str()))
    {
        return Err(SchemaError::UnknownKeyword);
    }
    let kind = object
        .get("type")
        .and_then(JcsValue::as_str)
        .and_then(SchemaType::from_name)
        .ok_or(SchemaError::BadType)?;
    let only_for = |keys: &[&str], wanted: SchemaType| {
        if kind != wanted && keys.iter().any(|key| object.contains_key(key)) {
            Err(SchemaError::WrongTypeForKeyword)
        } else {
            Ok(())
        }
    };
    only_for(
        &["properties", "required", "additionalProperties"],
        SchemaType::Object,
    )?;
    only_for(&["minLength", "maxLength"], SchemaType::String)?;
    only_for(&["minimum", "maximum"], SchemaType::Integer)?;
    only_for(&["minItems", "maxItems"], SchemaType::Array)?;

    let properties = match (object.get("properties"), object.get("additionalProperties")) {
        (None, None) => None,
        (Some(members), Some(JcsValue::Bool(false))) => {
            let members = members.as_object().ok_or(SchemaError::NotObject)?;
            let next = depth.checked_add(1).ok_or(SchemaError::TooLarge)?;
            let mut parsed = BTreeMap::new();
            for (name, child) in members.entries() {
                parsed.insert(name.as_str().to_owned(), node(child, next, budget)?);
            }
            Some(parsed)
        }
        _ => return Err(SchemaError::OpenObject),
    };
    let mut required = BTreeSet::new();
    if let Some(names) = object.get("required") {
        let listed = properties.as_ref().ok_or(SchemaError::BadRequired)?;
        for name in names.as_array().ok_or(SchemaError::BadRequired)? {
            let name = name.as_str().ok_or(SchemaError::BadRequired)?;
            if !listed.contains_key(name) || !required.insert(name.to_owned()) {
                return Err(SchemaError::BadRequired);
            }
        }
    }
    let allowed = match object.get("enum") {
        None => None,
        Some(values) => {
            let values = values.as_array().ok_or(SchemaError::BadEnum)?;
            let fits = |item: &JcsValue| item.is_scalar() && kind.admits(item);
            let distinct = values
                .iter()
                .enumerate()
                .all(|(index, item)| !values.iter().take(index).any(|other| other == item));
            if values.is_empty() || !values.iter().all(fits) || !distinct {
                return Err(SchemaError::BadEnum);
            }
            Some(values.to_vec())
        }
    };
    let count = |key: &str| -> Result<Option<u64>, SchemaError> {
        object
            .get(key)
            .map(|bound| {
                bound
                    .as_i64()
                    .and_then(|bound| u64::try_from(bound).ok())
                    .ok_or(SchemaError::BadBound)
            })
            .transpose()
    };
    let integer = |key: &str| -> Result<Option<i64>, SchemaError> {
        object
            .get(key)
            .map(|bound| {
                bound
                    .as_i64()
                    .filter(|bound| bound.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs())
                    .ok_or(SchemaError::BadBound)
            })
            .transpose()
    };
    let parsed = SchemaNode {
        kind,
        properties,
        required,
        allowed,
        min_length: count("minLength")?,
        max_length: count("maxLength")?,
        minimum: integer("minimum")?,
        maximum: integer("maximum")?,
        min_items: count("minItems")?,
        max_items: count("maxItems")?,
    };
    let ordered = |low: Option<u64>, high: Option<u64>| low.zip(high).is_none_or(|(l, h)| l <= h);
    if !ordered(parsed.min_length, parsed.max_length)
        || !ordered(parsed.min_items, parsed.max_items)
        || parsed
            .minimum
            .zip(parsed.maximum)
            .is_some_and(|(low, high)| low > high)
    {
        return Err(SchemaError::BadBound);
    }
    Ok(parsed)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::jcs::ParseOptions;

    fn value(text: &str) -> JcsValue {
        jcs::parse_with(text.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value
    }

    fn schema(text: &str) -> Result<ArgSchema, SchemaError> {
        ArgSchema::parse(&value(text))
    }

    const PAY: &str = r#"{"type":"object","additionalProperties":false,
        "required":["invoice_id","amount","currency"],
        "properties":{
          "invoice_id":{"type":"string","maxLength":64},
          "amount":{"type":"integer","minimum":0,"maximum":9007199254740991},
          "currency":{"type":"string","minLength":3,"maxLength":3,"enum":["USD","EUR"]},
          "memo":{"type":"string","maxLength":8},
          "to":{"type":"object","additionalProperties":false,"required":["recipient"],
                "properties":{"recipient":{"type":"string"},"note":{"type":"string"}}},
          "tags":{"type":"array","maxItems":2},
          "extra":{"type":"object"}}}"#;

    #[test]
    fn accepts_what_it_declares() {
        let pay = schema(PAY).unwrap();
        for ok in [
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD"}"#,
            r#"{"invoice_id":"INV-1","amount":0,"currency":"EUR","memo":"éééééééé"}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","to":{"recipient":"r"}}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","tags":[1,{"a":2}]}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","extra":{"anything":[1]}}"#,
        ] {
            assert!(pay.accepts(&value(ok)), "{ok}");
        }
    }

    #[test]
    fn refuses_what_it_does_not() {
        let pay = schema(PAY).unwrap();
        for bad in [
            // A member it does not declare, at the top or nested.
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","verbose":true}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","to":{"recipient":"r","account":"x"}}"#,
            // A required member missing, at the top or nested.
            r#"{"invoice_id":"INV-1","amount":5}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","to":{"note":"n"}}"#,
            // Wrong types.
            r#"{"invoice_id":7,"amount":5,"currency":"USD"}"#,
            r#"{"invoice_id":"INV-1","amount":"5","currency":"USD"}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","to":"r"}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","extra":[1]}"#,
            // Out of range, length, enum or count.
            r#"{"invoice_id":"INV-1","amount":-1,"currency":"USD"}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"GBP"}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","memo":"123456789"}"#,
            r#"{"invoice_id":"INV-1","amount":5,"currency":"USD","tags":[1,2,3]}"#,
            // Not an object at all.
            r"[]",
        ] {
            assert!(!pay.accepts(&value(bad)), "{bad}");
        }
    }

    #[test]
    fn leaves_are_the_declared_arguments() {
        let pay = schema(PAY).unwrap();
        let leaves: Vec<(String, bool)> = pay
            .leaves()
            .into_iter()
            .map(|leaf| (leaf.pointer, leaf.always_present))
            .collect();
        assert_eq!(
            leaves,
            [
                ("/amount", true),
                ("/currency", true),
                ("/extra", false),
                ("/invoice_id", true),
                ("/memo", false),
                ("/tags", false),
                ("/to/note", false),
                ("/to/recipient", false),
            ]
            .map(|(pointer, present)| (pointer.to_owned(), present))
        );
        // Names are escaped as RFC 6901 tokens.
        let odd = schema(
            r#"{"type":"object","additionalProperties":false,"properties":{"a/b~c":{"type":"null"}}}"#,
        )
        .unwrap();
        assert_eq!(odd.leaves()[0].pointer, "/a~1b~0c");
    }

    #[test]
    fn only_the_strict_subset_parses() {
        let refused = [
            (r"[]", SchemaError::NotObject),
            (r#"{"type":"string"}"#, SchemaError::BadRoot),
            (r#"{"type":"object"}"#, SchemaError::BadRoot),
            (
                r#"{"type":"object","properties":{}}"#,
                SchemaError::OpenObject,
            ),
            (
                r#"{"type":"object","properties":{},"additionalProperties":true}"#,
                SchemaError::OpenObject,
            ),
            (
                r#"{"type":"object","additionalProperties":false}"#,
                SchemaError::OpenObject,
            ),
            (
                r#"{"type":["object","null"],"properties":{},"additionalProperties":false}"#,
                SchemaError::BadType,
            ),
            (
                r#"{"type":"object","properties":{},"additionalProperties":false,"description":"x"}"#,
                SchemaError::UnknownKeyword,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","pattern":"^a$"}},"additionalProperties":false}"#,
                SchemaError::UnknownKeyword,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","default":"x"}},"additionalProperties":false}"#,
                SchemaError::UnknownKeyword,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}"#,
                SchemaError::UnknownKeyword,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","minimum":1}},"additionalProperties":false}"#,
                SchemaError::WrongTypeForKeyword,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"number","minimum":0.5}},"additionalProperties":false}"#,
                SchemaError::WrongTypeForKeyword,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"integer","minimum":0.5}},"additionalProperties":false}"#,
                SchemaError::BadBound,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"integer","maximum":9007199254740992}},"additionalProperties":false}"#,
                SchemaError::BadBound,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","minLength":5,"maxLength":4}},"additionalProperties":false}"#,
                SchemaError::BadBound,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","maxLength":-1}},"additionalProperties":false}"#,
                SchemaError::BadBound,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string"}},"required":["b"],"additionalProperties":false}"#,
                SchemaError::BadRequired,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string"}},"required":["a","a"],"additionalProperties":false}"#,
                SchemaError::BadRequired,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","enum":[]}},"additionalProperties":false}"#,
                SchemaError::BadEnum,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","enum":["x","x"]}},"additionalProperties":false}"#,
                SchemaError::BadEnum,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"string","enum":[1]}},"additionalProperties":false}"#,
                SchemaError::BadEnum,
            ),
            (
                r#"{"type":"object","properties":{"a":{"type":"object","enum":[{}]}},"additionalProperties":false}"#,
                SchemaError::BadEnum,
            ),
        ];
        for (text, error) in refused {
            assert_eq!(schema(text), Err(error), "{text}");
        }
    }

    #[test]
    fn size_is_bounded() {
        let mut deep = r#"{"type":"string"}"#.to_owned();
        for _ in 0..MAX_SCHEMA_DEPTH {
            deep = format!(
                r#"{{"type":"object","additionalProperties":false,"properties":{{"a":{deep}}}}}"#
            );
        }
        assert_eq!(schema(&deep), Err(SchemaError::TooLarge));
        let wide: Vec<String> = (0..MAX_SCHEMA_NODES)
            .map(|n| format!(r#""p{n}":{{"type":"null"}}"#))
            .collect();
        let wide = format!(
            r#"{{"type":"object","additionalProperties":false,"properties":{{{}}}}}"#,
            wide.join(",")
        );
        assert_eq!(schema(&wide), Err(SchemaError::TooLarge));
    }
}
