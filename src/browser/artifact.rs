//! Browser delivery of an HTTP-Artifact.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.

use super::forms::FormField;
use crate::artifact::Artifact;
use crate::constants::url_params;
use crate::error::SamlError;
use crate::model::RelayStateParam;

/// How an artifact is encoded for the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactEncoding {
    /// `SAMLart` query parameter on a redirect.
    Url,
    /// `SAMLart` hidden control in a POST form.
    Form,
}

/// How an identity provider hands a response artifact to the browser.
///
/// The index selects the identity provider's SOAP `ArtifactResolutionService`
/// the service provider will call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactDelivery {
    endpoint_index: u16,
    encoding: ArtifactEncoding,
}

impl ArtifactDelivery {
    /// `Cache-Control` value to send with the HTTP response that carries the
    /// artifact.
    pub const CACHE_CONTROL: &'static str = "no-cache, no-store";

    /// `Pragma` value to send with the HTTP response that carries the
    /// artifact.
    pub const PRAGMA: &'static str = "no-cache";

    /// Deliver the artifact in a redirect URL. Send it with HTTP 302 or 303.
    pub fn redirect(endpoint_index: u16) -> Self {
        Self {
            endpoint_index,
            encoding: ArtifactEncoding::Url,
        }
    }

    /// Deliver the artifact in an auto-submitted POST form.
    pub fn post_form(endpoint_index: u16) -> Self {
        Self {
            endpoint_index,
            encoding: ArtifactEncoding::Form,
        }
    }

    pub(crate) fn endpoint_index(self) -> u16 {
        self.endpoint_index
    }

    pub(crate) fn encoding(self) -> ArtifactEncoding {
        self.encoding
    }
}

/// Artifact and RelayState a browser delivered to an assertion consumer.
///
/// Resolve [`Self::artifact`] with
/// [`Saml<Sp>::resolve_artifact`](crate::Saml::resolve_artifact), then pass
/// this value and the resolved message to
/// [`BrowserInput::artifact`](crate::BrowserInput::artifact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredArtifact {
    artifact: Artifact,
    relay_state: RelayStateParam,
}

impl DeliveredArtifact {
    /// Read the artifact from the query string of an HTTP GET.
    ///
    /// The query may start with `?`. Parameters other than `SAMLart` and
    /// `RelayState` are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `SAMLart` is missing or repeated,
    /// is not a type 0x0004 artifact, or `RelayState` is repeated or longer
    /// than 80 bytes.
    pub fn from_query(raw_query: &str) -> Result<Self, SamlError> {
        let pairs: Vec<(String, String)> =
            url::form_urlencoded::parse(raw_query.trim_start_matches('?').as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect();
        Self::from_pairs(
            pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
    }

    /// Read the artifact from the form fields of an HTTP POST.
    ///
    /// Fields other than `SAMLart` and `RelayState` are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `SAMLart` is missing or repeated,
    /// is not a type 0x0004 artifact, or `RelayState` is repeated or longer
    /// than 80 bytes.
    pub fn from_form(fields: &[FormField]) -> Result<Self, SamlError> {
        Self::from_pairs(fields.iter().map(|field| (field.name(), field.value())))
    }

    /// Artifact to resolve.
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// RelayState delivered with the artifact.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
    }

    fn from_pairs<'a>(
        pairs: impl Iterator<Item = (&'a str, &'a str)> + Clone,
    ) -> Result<Self, SamlError> {
        let artifact = single_value(pairs.clone(), url_params::SAML_ART)?
            .ok_or_else(|| SamlError::Invalid(format!("missing {}", url_params::SAML_ART)))?;
        let relay_state = single_value(pairs, url_params::RELAY_STATE)?;
        Ok(Self {
            artifact: Artifact::try_from_encoded(artifact)?,
            relay_state: RelayStateParam::try_from_option(relay_state)?,
        })
    }
}

fn single_value<'a>(
    pairs: impl Iterator<Item = (&'a str, &'a str)>,
    name: &str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = pairs
        .filter(|(field, _)| *field == name)
        .map(|(_, value)| value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid(format!("ambiguous {name}")));
    }
    Ok(first)
}
