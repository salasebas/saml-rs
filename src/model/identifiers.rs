use std::fmt;

use crate::error::SamlError;

macro_rules! non_empty_text {
    ($(#[$type_doc:meta])* $name:ident, $label:literal) => {
        $(#[$type_doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Create the ", $label, " from its text.")]
            ///
            /// # Errors
            ///
            #[doc = concat!(
                "Returns [`SamlError::Invalid`] when the ",
                $label,
                " has no non-whitespace character."
            )]
            pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(SamlError::Invalid(
                        concat!($label, " must not be empty").into(),
                    ));
                }
                Ok(Self(value))
            }

            #[doc = concat!("Borrow the ", $label, " text.")]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

non_empty_text!(
    /// SAML protocol message `ID`.
    MessageId,
    "SAML message ID"
);

non_empty_text!(
    /// `ID` of a SAML assertion.
    AssertionId,
    "assertion ID"
);

non_empty_text!(
    /// SAML `xs:dateTime` instant text carried in pending snapshots and parsed
    /// results.
    ///
    /// `try_new` stores the text unchanged and does not parse it. The
    /// validation that consumes the instant parses and enforces it.
    SamlInstant,
    "SAML instant"
);

non_empty_text!(
    /// `SessionIndex` from an `AuthnStatement` or `LogoutRequest`.
    SessionIndex,
    "SessionIndex"
);
