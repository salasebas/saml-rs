//! The [`Value`] field tree that the XML extractor returns.

use std::collections::HashMap;

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
    #[cfg(test)]
    pub(crate) fn get_key(&self, key: &str) -> Option<&Value> {
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
    #[cfg(test)]
    pub(crate) fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// True when this value is [`Value::Null`].
    #[cfg(test)]
    pub(crate) fn is_null(&self) -> bool {
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

/// Strip a certificate PEM down to its bare base64 body.
pub(crate) fn normalize_cert_string(cert: &str) -> String {
    cert.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(['\n', '\r', ' ', '\t'], "")
}

/// camelCase an identifier, matching the npm `camelcase` defaults for the
/// PascalCase SAML attribute names used across the field-sets and templates.
pub(crate) fn camel_case(input: &str) -> String {
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
pub(crate) fn zip_object(keys: &[String], values: Vec<Value>, skip_duplicated: bool) -> Value {
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
