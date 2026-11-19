use std::fmt;

use crate::error::SamlError;

macro_rules! text_identifier {
    ($(#[$type_doc:meta])* $name:ident, $label:literal) => {
        $(#[$type_doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validate and wrap a ", $label, ".")]
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

text_identifier!(
    /// SAML protocol message `ID`.
    MessageId,
    "SAML message ID"
);

text_identifier!(
    /// `ID` of a SAML assertion.
    AssertionId,
    "assertion ID"
);

text_identifier!(
    /// SAML `xs:dateTime` instant text carried in pending snapshots and parsed
    /// results.
    ///
    /// The value is kept as received. The validation that consumes it parses
    /// and enforces the instant.
    SamlInstant,
    "SAML instant"
);

text_identifier!(
    /// `SessionIndex` from an `AuthnStatement` or `LogoutRequest`.
    SessionIndex,
    "SessionIndex"
);
