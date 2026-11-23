use std::fmt;
use std::hash::{Hash, Hasher};

use super::attributes::{Attribute, AttributeNameFormat, AttributeValue, Attributes};
use crate::constants::attribute_name::{PAIRWISE_ID, SUBJECT_ID};
use crate::error::SamlError;
use crate::xml::dom::is_xml_whitespace_char;

const MAX_PART_LEN: usize = 127;

macro_rules! scoped_identifier {
    ($(#[$type_doc:meta])* $name:ident, $attribute_name:expr, $label:literal) => {
        $(#[$type_doc])*
        #[derive(Debug, Clone)]
        pub struct $name {
            value: String,
            separator: usize,
        }

        impl $name {
            #[doc = concat!("Create the ", $label, " from its `uniqueID@scope` text.")]
            ///
            /// The unique ID is 1 to 127 ASCII letters, digits, `=`, and `-`.
            /// The scope is 1 to 127 ASCII letters, digits, `-`, and `.`. Each
            /// starts with a letter or a digit.
            ///
            /// # Errors
            ///
            /// Returns [`SamlError::Invalid`] when `value` does not have that
            /// form, including when it has leading or trailing whitespace.
            pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
                let value = value.into();
                let separator = scope_separator(&value).ok_or_else(|| {
                    SamlError::Invalid(concat!($label, " must be uniqueID@scope").into())
                })?;
                Ok(Self { value, separator })
            }

            pub(crate) fn received(attributes: &Attributes) -> Result<Option<Self>, SamlError> {
                let Some(value) = received_value(attributes, $attribute_name)? else {
                    return Ok(None);
                };
                let separator = scope_separator(value).ok_or_else(|| {
                    SamlError::ProtocolProfile(format!(
                        "`{}` attribute value is not uniqueID@scope",
                        $attribute_name
                    ))
                })?;
                Ok(Some(Self {
                    value: value.to_string(),
                    separator,
                }))
            }

            /// The whole `uniqueID@scope` value, in the case it was created
            /// or received with.
            pub fn as_str(&self) -> &str {
                &self.value
            }

            /// The unique ID: the text before `@`.
            pub fn unique_id(&self) -> &str {
                &self.value[..self.separator]
            }

            /// The scope: the text after `@`.
            pub fn scope(&self) -> &str {
                &self.value[self.separator + 1..]
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.value.eq_ignore_ascii_case(&other.value)
            }
        }

        impl Eq for $name {}

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                for byte in self.value.bytes() {
                    state.write_u8(byte.to_ascii_lowercase());
                }
                state.write_u8(0xff);
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.value)
            }
        }

        impl From<$name> for Attribute {
            #[doc = concat!(
                "The `", $label, "` attribute: its `Name`, the `uri` `NameFormat`, and the value."
            )]
            fn from(identifier: $name) -> Self {
                Attribute::new($attribute_name, [AttributeValue::new(identifier.value)])
                    .with_name_format(AttributeNameFormat::Uri)
            }
        }
    };
}

scoped_identifier!(
    /// A `subject-id` value: a long-lived identifier of the subject, the same
    /// for every service provider.
    ///
    /// Two values are equal when they differ only in ASCII case, and they then
    /// identify the same subject. [`Hash`] agrees with that equality.
    ///
    /// An identity provider adds it to an assertion as an [`Attribute`]. The
    /// response is rejected when the scope has an upper case letter, or the
    /// unique ID has both upper and lower case letters. A service provider
    /// reads it with [`crate::SsoSession::subject_id`].
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{Attribute, Attributes, NameId, SamlError, SsoAssertion, SubjectId};
    ///
    /// # fn main() -> Result<(), SamlError> {
    /// let subject_id = SubjectId::try_new("idm123456789@example.com")?;
    /// assert_eq!(subject_id.unique_id(), "idm123456789");
    /// assert_eq!(subject_id.scope(), "example.com");
    /// assert_eq!(subject_id, SubjectId::try_new("IDM123456789@EXAMPLE.COM")?);
    ///
    /// let assertion = SsoAssertion::new(NameId::generate_transient())
    ///     .with_attributes(Attributes::new([Attribute::from(subject_id)]));
    /// # let _ = assertion;
    /// # Ok(())
    /// # }
    /// ```
    SubjectId,
    SUBJECT_ID,
    "subject-id"
);

scoped_identifier!(
    /// A `pairwise-id` value: a long-lived identifier of the subject that
    /// differs for each service provider.
    ///
    /// Two values are equal when they differ only in ASCII case. [`Hash`]
    /// agrees with that equality. Equal values from one identity provider
    /// identify one subject at one service provider. The same value at
    /// another service provider, or from another identity provider, can
    /// identify another subject.
    ///
    /// An identity provider adds it to an assertion as an [`Attribute`]. The
    /// response is rejected when the scope has an upper case letter, or the
    /// unique ID has both upper and lower case letters. A service provider
    /// reads it with [`crate::SsoSession::pairwise_id`].
    ///
    /// The identity provider gives each subject one value per service
    /// provider, the same value on every login, and a different value for
    /// another service provider. The service provider must not be able to
    /// map it to the subject's identifier at another service provider. One
    /// way to derive the unique ID is a keyed hash of the service provider's
    /// entity ID and the local account, written in a case-insensitive encoding
    /// such as lowercase hexadecimal or Base32. Base64 is not safe: two of its
    /// values can differ only in case. Keep the key secret and stable, because
    /// a new key gives every subject new values.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{EntityId, PairwiseId, SamlError};
    ///
    /// /// `hmac_sha256` is the application's HMAC-SHA-256 under its secret key.
    /// fn pairwise_id(
    ///     hmac_sha256: impl Fn(&[u8]) -> [u8; 32],
    ///     service_provider: &EntityId,
    ///     account: &str,
    /// ) -> Result<PairwiseId, SamlError> {
    ///     // XML cannot carry U+0000, so no entity ID contains the separator.
    ///     let input = [service_provider.as_str().as_bytes(), b"\0", account.as_bytes()].concat();
    ///     let unique_id: String = hmac_sha256(&input)
    ///         .iter()
    ///         .map(|byte| format!("{byte:02x}"))
    ///         .collect();
    ///     PairwiseId::try_new(format!("{unique_id}@example.org"))
    /// }
    /// # fn main() -> Result<(), SamlError> {
    /// # let sp = EntityId::try_new("https://sp.example.com/metadata")?;
    /// # let id = pairwise_id(|_| [0xab; 32], &sp, "alice")?;
    /// # assert_eq!(id.unique_id().len(), 64);
    /// # Ok(())
    /// # }
    /// ```
    PairwiseId,
    PAIRWISE_ID,
    "pairwise-id"
);

/// Byte offset of the `@` between the unique ID and the scope, when `value`
/// is `uniqueID@scope`.
fn scope_separator(value: &str) -> Option<usize> {
    let (unique_id, scope) = value.split_once('@')?;
    let is_unique_id = is_part(unique_id, |byte| matches!(byte, b'=' | b'-'));
    let is_scope = is_part(scope, |byte| matches!(byte, b'-' | b'.'));
    (is_unique_id && is_scope).then_some(unique_id.len())
}

fn is_part(part: &str, is_punctuation: impl Fn(u8) -> bool) -> bool {
    let bytes = part.as_bytes();
    bytes.len() <= MAX_PART_LEN
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || is_punctuation(byte))
}

/// The one value of the received attributes `name`, without its leading and
/// trailing XML whitespace.
fn received_value<'a>(
    attributes: &'a Attributes,
    name: &str,
) -> Result<Option<&'a str>, SamlError> {
    let matching: Vec<&Attribute> = attributes
        .iter()
        .filter(|attribute| is_attribute(attribute, name))
        .collect();
    if matching.is_empty() {
        return Ok(None);
    }
    let values: Vec<&AttributeValue> = matching
        .iter()
        .flat_map(|attribute| attribute.values())
        .collect();
    match values.as_slice() {
        [value] => Ok(Some(value.as_str().trim_matches(is_xml_whitespace_char))),
        _ => Err(SamlError::ProtocolProfile(format!(
            "`{name}` attribute must have exactly one AttributeValue"
        ))),
    }
}

/// Whether `attribute` is `subject-id` or `pairwise-id`.
pub(crate) fn is_subject_identifier(attribute: &Attribute) -> bool {
    is_attribute(attribute, SUBJECT_ID) || is_attribute(attribute, PAIRWISE_ID)
}

/// Check the `subject-id` and `pairwise-id` attributes of an assertion the
/// identity provider issues.
///
/// # Errors
///
/// Returns [`SamlError::Invalid`] when either attribute occurs more than once,
/// does not have exactly one value, has a value that is not `uniqueID@scope`,
/// has a scope with an upper case letter, or has a unique ID with both upper
/// and lower case letters.
pub(crate) fn check_issued_subject_identifiers(attributes: &[Attribute]) -> Result<(), SamlError> {
    for name in [SUBJECT_ID, PAIRWISE_ID] {
        let mut issued = attributes
            .iter()
            .filter(|attribute| is_attribute(attribute, name));
        let Some(attribute) = issued.next() else {
            continue;
        };
        if issued.next().is_some() {
            return Err(SamlError::Invalid(format!(
                "an assertion carries at most one `{name}` attribute"
            )));
        }
        let [value] = attribute.values() else {
            return Err(SamlError::Invalid(format!(
                "`{name}` attribute must have exactly one value"
            )));
        };
        let value = value.as_str();
        let separator = scope_separator(value).ok_or_else(|| {
            SamlError::Invalid(format!("`{name}` attribute value must be uniqueID@scope"))
        })?;
        let (unique_id, scope) = (&value[..separator], &value[separator + 1..]);
        if scope.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(SamlError::Invalid(format!(
                "`{name}` attribute scope must be lower case"
            )));
        }
        if unique_id.bytes().any(|byte| byte.is_ascii_uppercase())
            && unique_id.bytes().any(|byte| byte.is_ascii_lowercase())
        {
            return Err(SamlError::Invalid(format!(
                "`{name}` attribute unique ID must be all upper case or all lower case"
            )));
        }
    }
    Ok(())
}

/// Whether `attribute` is the attribute `name`: its `NameFormat` is `uri`,
/// `unspecified`, or absent.
fn is_attribute(attribute: &Attribute, name: &str) -> bool {
    attribute.name() == name
        && matches!(
            attribute.name_format(),
            None | Some(AttributeNameFormat::Uri | AttributeNameFormat::Unspecified)
        )
}
