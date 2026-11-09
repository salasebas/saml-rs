//! Small helper types and normalization functions.
//!
//! Base64 and DEFLATE live in [`crate::binding`]; this module covers the
//! certificate/key string normalisation and collection helpers used by the
//! extractor and metadata layers.

use std::collections::{HashMap, HashSet};

/// A dynamically-typed value tree produced by the XML extractor.
///
/// Dotted-path [`Value::get`] lookups support extracted SAML field trees such
/// as `request.id`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Value {
    /// Absent value.
    #[default]
    Null,
    /// Text value.
    Str(String),
    /// Ordered list of values.
    Array(Vec<Value>),
    /// Ordered key/value map (insertion order preserved).
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Walk a dotted `path` through nested objects.
    ///
    /// Returns `None` when any segment is missing or a non-object is traversed.
    pub fn get(&self, path: &str) -> Option<&Value> {
        let mut current = self;
        for segment in path.split('.') {
            let Value::Object(entries) = current else {
                return None;
            };
            current = entries.iter().find(|(k, _)| k == segment).map(|(_, v)| v)?;
        }
        Some(current)
    }

    /// Convenience: dotted-path lookup returning the string at that path.
    pub fn get_str(&self, path: &str) -> Option<&str> {
        self.get(path).and_then(Value::as_str)
    }

    /// Look up a single key verbatim (no dotted-path splitting).
    ///
    /// Use this for maps whose keys may contain `.` (e.g. binding URNs).
    pub fn get_key(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Borrow the inner string, if this is a [`Value::Str`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Borrow the inner slice, if this is a [`Value::Array`].
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// True when this value is [`Value::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Insert or replace `key` in an object value (no-op on non-objects).
    pub fn insert(&mut self, key: &str, value: Value) {
        if let Value::Object(entries) = self {
            if let Some(slot) = entries.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
            } else {
                entries.push((key.to_string(), value));
            }
        }
    }
}

fn strip_pem(input: &str, label: &str) -> String {
    input
        .replace(&format!("-----BEGIN {label}-----"), "")
        .replace(&format!("-----END {label}-----"), "")
        .replace(['\n', '\r', ' ', '\t'], "")
}

/// Strip a certificate PEM down to its bare base64 body.
pub fn normalize_cert_string(cert: &str) -> String {
    strip_pem(cert, "CERTIFICATE")
}

/// Strip an RSA private-key PEM down to its bare base64 body.
pub fn normalize_pem_string(pem: &str) -> String {
    strip_pem(pem, "RSA PRIVATE KEY")
}

/// A single value or a list of values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneOrMany<T> {
    /// Exactly one value.
    One(T),
    /// Zero or more values.
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    /// Collapse into a `Vec`.
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v],
            OneOrMany::Many(v) => v,
        }
    }
}

/// Normalise an optional single-or-many value into a `Vec`.
pub fn cast_array_opt<T>(value: Option<OneOrMany<T>>) -> Vec<T> {
    value.map(OneOrMany::into_vec).unwrap_or_default()
}

/// True when the slice is non-empty.
pub fn is_non_empty_array<T>(items: &[T]) -> bool {
    !items.is_empty()
}

/// Verify that every value in `field` equals `meta_field`.
///
/// Empty input is treated as a mismatch.
pub fn verify_fields(field: &[String], meta_field: &str) -> bool {
    !field.is_empty() && field.iter().all(|f| f == meta_field)
}

/// De-duplicate strings, preserving first-seen order.
pub fn uniq<I, S>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for item in items {
        let s = item.into();
        if seen.insert(s.clone()) {
            unique.push(s);
        }
    }
    unique
}

/// Last element of a slice.
pub fn last<T>(items: &[T]) -> Option<&T> {
    items.last()
}

/// camelCase an identifier, matching the npm `camelcase` defaults for the
/// PascalCase SAML attribute names used across the field-sets and templates.
pub fn camel_case(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    for i in 0..chars.len() {
        let c = chars[i];
        if matches!(c, '-' | '_' | ' ' | '.' | '/' | ':') {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if !cur.is_empty() {
            let prev = chars[i - 1];
            let lower_to_upper = prev.is_lowercase() && c.is_uppercase();
            let acronym_end = prev.is_uppercase()
                && c.is_uppercase()
                && i + 1 < chars.len()
                && chars[i + 1].is_lowercase();
            if lower_to_upper || acronym_end {
                words.push(std::mem::take(&mut cur));
            }
        }
        cur.push(c);
    }
    if !cur.is_empty() {
        words.push(cur);
    }

    let mut out = String::new();
    for (i, word) in words.iter().enumerate() {
        let lower = word.to_lowercase();
        if i == 0 {
            out.push_str(&lower);
            continue;
        }
        let mut it = lower.chars();
        if let Some(first) = it.next() {
            out.extend(first.to_uppercase());
            out.push_str(it.as_str());
        }
    }
    out
}

/// Build an object from parallel key/value lists.
///
/// When `skip_duplicated` is true the last value for a key wins; otherwise
/// duplicate keys are aggregated into a [`Value::Array`].
pub fn zip_object(keys: &[String], values: Vec<Value>, skip_duplicated: bool) -> Value {
    let mut out: Vec<(String, Value)> = Vec::new();
    let mut positions: HashMap<&str, usize> = HashMap::new();
    for (key, value) in keys.iter().zip(values) {
        let Some(&position) = positions.get(key.as_str()) else {
            positions.insert(key, out.len());
            out.push((key.clone(), value));
            continue;
        };
        let slot = &mut out[position].1;
        if skip_duplicated {
            *slot = value;
            continue;
        }
        match slot {
            Value::Array(items) => items.push(value),
            existing => {
                let prev = std::mem::take(existing);
                *existing = Value::Array(vec![prev, value]);
            }
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_cert_strips_header_and_whitespace() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB AgID\r\n\t-----END CERTIFICATE-----\n";
        assert_eq!(normalize_cert_string(pem), "MIIBAgID");
    }

    #[test]
    fn normalize_pem_strips_rsa_label() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";
        assert_eq!(normalize_pem_string(pem), "AAAA");
    }

    #[test]
    fn get_walks_dotted_path_with_default() {
        let v = Value::Object(vec![(
            "request".into(),
            Value::Object(vec![("id".into(), Value::Str("_abc".into()))]),
        )]);
        assert_eq!(v.get_str("request.id"), Some("_abc"));
        assert_eq!(v.get("request.missing"), None);
        // default fallback, lodash-style
        assert_eq!(v.get_str("nope.id").unwrap_or(""), "");
    }

    #[test]
    fn cast_array_opt_modes() {
        assert_eq!(cast_array_opt::<i32>(None), Vec::<i32>::new());
        assert_eq!(cast_array_opt(Some(OneOrMany::One(1))), vec![1]);
        assert_eq!(
            cast_array_opt(Some(OneOrMany::Many(vec![1, 2]))),
            vec![1, 2]
        );
    }

    #[test]
    fn uniq_and_last() {
        assert_eq!(uniq(["a", "b", "a", "c"]), vec!["a", "b", "c"]);
        assert_eq!(last(&[1, 2, 3]), Some(&3));
        assert_eq!(last::<i32>(&[]), None);
        assert!(is_non_empty_array(&[0]));
        assert!(!is_non_empty_array::<i32>(&[]));
    }

    #[test]
    fn verify_fields_all_match_non_empty() {
        assert!(verify_fields(&["a".to_string()], "a"));
        assert!(verify_fields(&["a".to_string(), "a".to_string()], "a"));
        assert!(!verify_fields(&["a".to_string(), "b".to_string()], "a"));
        assert!(!verify_fields(&[], "a"));
    }

    #[test]
    fn zip_object_skip_vs_aggregate() {
        let keys = vec!["a".to_string(), "a".to_string()];
        let skip = zip_object(
            &keys,
            vec![Value::Str("1".into()), Value::Str("2".into())],
            true,
        );
        assert_eq!(skip.get_str("a"), Some("2"));

        let agg = zip_object(
            &keys,
            vec![Value::Str("1".into()), Value::Str("2".into())],
            false,
        );
        assert_eq!(
            agg.get("a"),
            Some(&Value::Array(vec![
                Value::Str("1".into()),
                Value::Str("2".into())
            ]))
        );
    }
}
