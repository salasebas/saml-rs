//! Service Provider metadata.

use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::xml::{ExtractorField, XmlLimits};
use std::ops::Deref;

/// Parsed AssertionConsumerService endpoint from SP metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcsMetadataEndpoint {
    /// Protocol binding.
    pub(crate) binding: Binding,
    /// Endpoint location.
    pub(crate) location: String,
    /// Metadata index, when declared.
    pub(crate) index: Option<u16>,
    /// Whether `isDefault` is the boolean `true` or `1`.
    pub(crate) is_default: bool,
    /// Whether `isDefault` is the boolean `false` or `0`.
    pub(crate) is_default_false: bool,
}

impl AcsMetadataEndpoint {
    /// Whether the binding is HTTP-POST or HTTP-POST-SimpleSign.
    pub(crate) fn accepts_posted_response(&self) -> bool {
        match self.binding {
            Binding::Post | Binding::SimpleSign => true,
            Binding::Redirect | Binding::Artifact => false,
        }
    }
}

/// Parsed SP metadata. Derefs to [`Metadata`] for the shared accessors.
#[derive(Debug, Clone)]
pub struct SpMetadata {
    inner: Metadata,
}

impl SpMetadata {
    /// Parse SP metadata XML.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits, or
    /// SP-specific metadata extraction fails.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        Self::from_xml_with_limits(xml, XmlLimits::default())
    }

    /// Parse SP metadata XML with explicit XML parser resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when XML parsing, parser resource limits, or
    /// SP-specific metadata extraction fails.
    pub fn from_xml_with_limits(xml: &str, limits: XmlLimits) -> Result<Self, SamlError> {
        let extra = vec![
            ExtractorField::new("spSSODescriptor", &["EntityDescriptor", "SPSSODescriptor"])
                .attrs(&["WantAssertionsSigned", "AuthnRequestsSigned"]),
            ExtractorField::new(
                "assertionConsumerService",
                &[
                    "EntityDescriptor",
                    "SPSSODescriptor",
                    "AssertionConsumerService",
                ],
            )
            .attrs(&["Binding", "Location", "isDefault", "index"]),
        ];
        Ok(Self {
            inner: Metadata::parse_with_limits(xml, extra, limits)?,
        })
    }

    /// `WantAssertionsSigned` flag.
    pub fn is_want_assertions_signed(&self) -> bool {
        self.inner
            .meta
            .get_str("spSSODescriptor.wantAssertionsSigned")
            == Some("true")
    }

    /// `AuthnRequestsSigned` flag.
    pub fn is_authn_request_signed(&self) -> bool {
        self.inner
            .meta
            .get_str("spSSODescriptor.authnRequestsSigned")
            == Some("true")
    }

    /// Default `AssertionConsumerService` location for `binding`.
    ///
    /// The default is the first endpoint for `binding` with `isDefault` true,
    /// otherwise the first whose `isDefault` is not false, otherwise the first.
    /// `true` and `1` are true. `false` and `0` are false.
    pub fn get_assertion_consumer_service(&self, binding: Binding) -> Option<String> {
        self.get_assertion_consumer_service_endpoint(binding)
            .map(|endpoint| endpoint.location)
    }

    /// Default `AssertionConsumerService` endpoint for `binding`.
    pub(crate) fn get_assertion_consumer_service_endpoint(
        &self,
        binding: Binding,
    ) -> Option<AcsMetadataEndpoint> {
        let endpoints = self
            .assertion_consumer_service_endpoints()
            .into_iter()
            .filter(|endpoint| endpoint.binding == binding)
            .collect();
        select_indexed_default(endpoints)
    }

    /// `AssertionConsumerService` endpoint with the declared metadata index.
    pub(crate) fn get_assertion_consumer_service_by_index(
        &self,
        index: u16,
    ) -> Result<Option<AcsMetadataEndpoint>, SamlError> {
        let mut matches = self
            .assertion_consumer_service_endpoints()
            .into_iter()
            .filter(|endpoint| endpoint.index == Some(index));
        let first = matches.next();
        if matches.next().is_some() {
            return Err(SamlError::Invalid(format!(
                "duplicate AssertionConsumerService index {index}"
            )));
        }
        Ok(first)
    }

    /// Assertion consumer locations a response can be posted to, in metadata
    /// order.
    pub(crate) fn assertion_consumer_locations(&self) -> Vec<String> {
        self.posted_response_endpoints()
            .into_iter()
            .map(|endpoint| endpoint.location)
            .collect()
    }

    /// Default assertion consumer location a response can be posted to.
    ///
    /// The candidates are the HTTP-POST and HTTP-POST-SimpleSign endpoints.
    /// Selection uses the same default rule as
    /// [`Self::get_assertion_consumer_service`].
    pub(crate) fn default_assertion_consumer_location(&self) -> Option<String> {
        select_indexed_default(self.posted_response_endpoints()).map(|endpoint| endpoint.location)
    }

    /// Whether metadata contains `location` for `binding`.
    pub(crate) fn has_assertion_consumer_service(&self, binding: Binding, location: &str) -> bool {
        self.assertion_consumer_service_endpoints()
            .iter()
            .any(|endpoint| endpoint.binding == binding && endpoint.location == location)
    }

    /// HTTP-POST and HTTP-POST-SimpleSign assertion consumer endpoints.
    fn posted_response_endpoints(&self) -> Vec<AcsMetadataEndpoint> {
        self.assertion_consumer_service_endpoints()
            .into_iter()
            .filter(AcsMetadataEndpoint::accepts_posted_response)
            .collect()
    }

    fn assertion_consumer_service_endpoints(&self) -> Vec<AcsMetadataEndpoint> {
        let Some(acs) = self.inner.meta.get("assertionConsumerService") else {
            return Vec::new();
        };
        as_object_list(acs)
            .into_iter()
            .filter_map(acs_metadata_endpoint_from_value)
            .collect()
    }
}

fn acs_metadata_endpoint_from_value(value: &crate::util::Value) -> Option<AcsMetadataEndpoint> {
    let binding = Binding::from_urn(value.get_str("binding")?)?;
    let location = value.get_str("location")?.to_string();
    let index = value
        .get_str("index")
        .and_then(|index| index.parse::<u16>().ok());
    let (is_default, is_default_false) = indexed_default_flags(value.get_str("isDefault"));
    Some(AcsMetadataEndpoint {
        binding,
        location,
        index,
        is_default,
        is_default_false,
    })
}

fn indexed_default_flags(is_default: Option<&str>) -> (bool, bool) {
    match is_default {
        Some("true" | "1") => (true, false),
        Some("false" | "0") => (false, true),
        Some(_) | None => (false, false),
    }
}

fn select_indexed_default(endpoints: Vec<AcsMetadataEndpoint>) -> Option<AcsMetadataEndpoint> {
    if let Some(index) = endpoints.iter().position(|endpoint| endpoint.is_default) {
        return endpoints.into_iter().nth(index);
    }
    if let Some(index) = endpoints
        .iter()
        .position(|endpoint| !endpoint.is_default_false)
    {
        return endpoints.into_iter().nth(index);
    }
    endpoints.into_iter().next()
}

impl Deref for SpMetadata {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::SpMetadata;
    use crate::constants::Binding;

    fn sp_with_acs(endpoints: &str) -> Result<SpMetadata, crate::error::SamlError> {
        let xml = format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{endpoints}</SPSSODescriptor></EntityDescriptor>"#
        );
        SpMetadata::from_xml(&xml)
    }

    #[test]
    fn assertion_consumer_service_follows_indexed_default() -> Result<(), Box<dyn std::error::Error>>
    {
        let second_default = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="true"/>"#,
        )?;
        assert_eq!(
            second_default
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/second")
        );

        let false_then_omitted = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="false"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/redirect" index="1" isDefault="true"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="2"/>"#,
        )?;
        assert_eq!(
            false_then_omitted
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/second")
        );
        assert_eq!(
            false_then_omitted
                .get_assertion_consumer_service(Binding::Redirect)
                .as_deref(),
            Some("https://sp.example.com/redirect")
        );

        let all_false = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="0"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="false"/>"#,
        )?;
        assert_eq!(
            all_false
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/first")
        );

        let numeric_true = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="0"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="1"/>"#,
        )?;
        assert_eq!(
            numeric_true
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/second")
        );

        let unrecognized = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="yes"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="false"/>"#,
        )?;
        assert_eq!(
            unrecognized
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/first")
        );
        Ok(())
    }
}
