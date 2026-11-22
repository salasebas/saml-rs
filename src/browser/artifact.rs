//! Browser delivery of an HTTP-Artifact.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.

use super::forms::FormField;
use crate::artifact::Artifact;
use crate::binding::single_parameter;
use crate::constants::url_params;
use crate::error::SamlError;
use crate::model::RelayState;

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
/// [`ServiceProvider::resolve_artifact`](crate::ServiceProvider::resolve_artifact), then pass
/// this value and the resolved message to
/// [`Inbound::artifact`](crate::Inbound::artifact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredArtifact {
    artifact: Artifact,
    relay_state: Option<RelayState>,
}

impl DeliveredArtifact {
    /// Read the artifact from the query string of an HTTP GET.
    ///
    /// The query may start with `?`. Parameters other than `SAMLart` and
    /// `RelayState` are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingBindingParameter`] when `SAMLart` is
    /// missing, [`SamlError::DuplicateBindingParameter`] when `SAMLart` or
    /// `RelayState` is repeated, [`SamlError::LimitExceeded`] when
    /// `RelayState` is longer than
    /// [`MAX_RECEIVED_RELAY_STATE_BYTES`](crate::MAX_RECEIVED_RELAY_STATE_BYTES),
    /// and [`SamlError::Invalid`] when `SAMLart` is not a type 0x0004 artifact.
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
    /// Returns [`SamlError::MissingBindingParameter`] when `SAMLart` is
    /// missing, [`SamlError::DuplicateBindingParameter`] when `SAMLart` or
    /// `RelayState` is repeated, [`SamlError::LimitExceeded`] when
    /// `RelayState` is longer than
    /// [`MAX_RECEIVED_RELAY_STATE_BYTES`](crate::MAX_RECEIVED_RELAY_STATE_BYTES),
    /// and [`SamlError::Invalid`] when `SAMLart` is not a type 0x0004 artifact.
    pub fn from_form(fields: &[FormField]) -> Result<Self, SamlError> {
        Self::from_pairs(fields.iter().map(|field| (field.name(), field.value())))
    }

    /// Artifact to resolve.
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// RelayState delivered with the artifact.
    pub fn relay_state(&self) -> Option<&RelayState> {
        self.relay_state.as_ref()
    }

    fn from_pairs<'a>(
        pairs: impl Iterator<Item = (&'a str, &'a str)> + Clone,
    ) -> Result<Self, SamlError> {
        let artifact = single_parameter(pairs.clone(), url_params::SAML_ART)?.ok_or(
            SamlError::MissingBindingParameter {
                name: url_params::SAML_ART,
            },
        )?;
        let relay_state = single_parameter(pairs, url_params::RELAY_STATE)?;
        Ok(Self {
            artifact: Artifact::try_new(artifact)?,
            relay_state: relay_state
                .map(|value| RelayState::received(value.to_string()))
                .transpose()?,
        })
    }
}
