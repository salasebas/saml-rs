use std::sync::Arc;

use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::protocol_element::SamlElement;
use crate::xml::XmlLimits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcsMetadataEndpoint {
    pub(crate) binding: Binding,
    pub(crate) location: String,
    pub(crate) index: Option<u16>,
    pub(crate) is_default: DefaultMarking,
    pub(crate) role: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultMarking {
    Default,
    Unmarked,
    NotDefault,
}

impl DefaultMarking {
    fn from_attribute(is_default: Option<&str>) -> Self {
        match crate::xml::xs_boolean(is_default) {
            Some(true) => Self::Default,
            Some(false) => Self::NotDefault,
            None => Self::Unmarked,
        }
    }
}

/// Parsed SP metadata. Use [`Self::as_metadata`] for role-scoped shared fields.
#[derive(Debug, Clone)]
pub struct SpMetadata {
    inner: Metadata,
    assertion_consumer_service_roles: Vec<Value>,
}

impl SpMetadata {
    /// Borrow shared metadata fields selected from this SAML 2.0 role.
    pub fn as_metadata(&self) -> &Metadata {
        &self.inner
    }

    /// Parse SP metadata XML with the default XML limits and no schema
    /// validator.
    ///
    /// Keys, flags, and endpoints are read from the entity's `SPSSODescriptor`
    /// elements in the SAML metadata namespace whose
    /// `protocolSupportEnumeration` lists `urn:oasis:names:tc:SAML:2.0:protocol`.
    /// Endpoints are the children of those descriptors in the SAML metadata
    /// namespace. A child with the same local name in another namespace is
    /// not an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when the entity has no such
    /// `SPSSODescriptor`. Returns [`SamlError::Invalid`] when a signing flag
    /// on a selected descriptor has an invalid `xs:boolean` value or uses the
    /// SAML metadata namespace. XML parsing, resource limits, and SP-specific
    /// metadata extraction can also fail.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        Self::from_xml_with_policy(xml, &crate::XmlPolicy::default())
    }

    /// Parse SP metadata XML as [`Self::from_xml`] does, with the XML limits
    /// and optional schema validator of `policy`.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::from_xml`] and any schema validation
    /// error from `policy`.
    pub fn from_xml_with_policy(xml: &str, policy: &crate::XmlPolicy) -> Result<Self, SamlError> {
        let (inner, roles) = Metadata::parse_role_with_policy(
            xml,
            super::SsoDescriptorRole::ServiceProvider,
            policy,
        )?;
        Ok(Self::from_roles(inner, &roles))
    }

    pub(crate) fn from_aggregate_entity(
        xml: &Arc<str>,
        path: &[&SamlElement],
        limits: XmlLimits,
    ) -> Result<Self, SamlError> {
        let (inner, roles) = Metadata::from_aggregate_entity(
            xml,
            path,
            super::SsoDescriptorRole::ServiceProvider,
            limits,
        )?;
        Ok(Self::from_roles(inner, &roles))
    }

    fn from_roles(mut inner: Metadata, roles: &[SamlElement]) -> Self {
        let assertion_consumer_service_roles = roles
            .iter()
            .map(|role| {
                super::endpoints::role_endpoints(
                    role,
                    "AssertionConsumerService",
                    &["Binding", "Location", "isDefault", "index"],
                )
            })
            .collect();
        inner.meta.insert(
            "manageNameIDService",
            super::endpoints::roles_endpoints(
                roles,
                "ManageNameIDService",
                &["Binding", "Location", "ResponseLocation"],
            ),
        );
        Self {
            inner,
            assertion_consumer_service_roles,
        }
    }

    /// `WantAssertionsSigned` flag.
    ///
    /// True when any SAML 2.0 `SPSSODescriptor` sets the attribute to `true`
    /// or `1`. An absent attribute is false.
    pub fn want_assertions_signed(&self) -> bool {
        self.inner.signing_flags.want_assertions_signed
    }

    /// `AuthnRequestsSigned` flag.
    ///
    /// True when any SAML 2.0 `SPSSODescriptor` sets the attribute to `true`
    /// or `1`. An absent attribute is false.
    pub fn authn_requests_signed(&self) -> bool {
        self.inner.signing_flags.authn_requests_signed
    }

    /// Default `AssertionConsumerService` location for `binding`.
    ///
    /// The location comes from the first SAML 2.0 `SPSSODescriptor` that
    /// publishes an endpoint for `binding`. Within that role, the default is
    /// the first endpoint for `binding` with `isDefault` true, otherwise the
    /// first whose `isDefault` is not false, otherwise the first. `true` and
    /// `1` are true. `false` and `0` are false.
    pub fn assertion_consumer_location(&self, binding: Binding) -> Option<String> {
        self.assertion_consumer_service_endpoint(binding)
            .map(|endpoint| endpoint.location)
    }

    pub(crate) fn assertion_consumer_service_endpoint(
        &self,
        binding: Binding,
    ) -> Option<AcsMetadataEndpoint> {
        self.assertion_consumer_service_roles
            .iter()
            .enumerate()
            .find_map(|(role, services)| {
                let endpoints = role_endpoints(role, services)
                    .filter(|endpoint| endpoint.binding == binding)
                    .collect();
                select_indexed_default(endpoints, |endpoint| endpoint.is_default)
            })
    }

    pub(crate) fn default_assertion_consumer_service_endpoint(
        &self,
    ) -> Result<Option<AcsMetadataEndpoint>, SamlError> {
        let Some(first_role) = self.assertion_consumer_service_roles.first() else {
            return Ok(None);
        };
        select_indexed_default(as_object_list(first_role), |value| {
            DefaultMarking::from_attribute(value.get_str("isDefault"))
        })
        .map(|value| {
            acs_metadata_endpoint_from_value(0, value).ok_or_else(|| {
                SamlError::Invalid(
                    "default AssertionConsumerService is unsupported or malformed".into(),
                )
            })
        })
        .transpose()
    }

    pub(crate) fn assertion_consumer_service_by_index(
        &self,
        index: u16,
    ) -> Result<Option<AcsMetadataEndpoint>, SamlError> {
        let mut found = None;
        for (role, services) in self.assertion_consumer_service_roles.iter().enumerate() {
            let Some(endpoint) = role_endpoint_at_index(services, index)? else {
                continue;
            };
            if found.is_some() {
                return Err(SamlError::Invalid(format!(
                    "AssertionConsumerService index {index} is published by more than one SPSSODescriptor"
                )));
            }
            found = Some((role, endpoint));
        }
        Ok(found.and_then(|(role, endpoint)| acs_metadata_endpoint_from_value(role, endpoint)))
    }

    pub(crate) fn assertion_consumer_service_locations(&self, binding: Binding) -> Vec<String> {
        self.assertion_consumer_service_endpoints()
            .filter(|endpoint| endpoint.binding == binding)
            .map(|endpoint| endpoint.location)
            .collect()
    }

    pub(crate) fn assertion_consumer_service_at(
        &self,
        binding: Binding,
        location: &str,
    ) -> Option<AcsMetadataEndpoint> {
        self.assertion_consumer_service_endpoints()
            .find(|endpoint| endpoint.binding == binding && endpoint.location == location)
    }

    #[cfg(crypto)]
    pub(crate) fn encryption_key_certificates(&self, acs: &AcsMetadataEndpoint) -> &[Vec<String>] {
        self.inner.role_encryption_key_certificates(acs.role)
    }

    fn assertion_consumer_service_endpoints(
        &self,
    ) -> impl Iterator<Item = AcsMetadataEndpoint> + '_ {
        self.assertion_consumer_service_roles
            .iter()
            .enumerate()
            .flat_map(|(role, services)| role_endpoints(role, services))
    }
}

fn role_endpoints(role: usize, services: &Value) -> impl Iterator<Item = AcsMetadataEndpoint> + '_ {
    as_object_list(services)
        .into_iter()
        .filter_map(move |value| acs_metadata_endpoint_from_value(role, value))
}

fn role_endpoint_at_index(services: &Value, index: u16) -> Result<Option<&Value>, SamlError> {
    let mut matches = as_object_list(services)
        .into_iter()
        .filter(|value| endpoint_index(value) == Some(index));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(SamlError::Invalid(format!(
            "duplicate AssertionConsumerService index {index}"
        )));
    }
    Ok(first)
}

fn acs_metadata_endpoint_from_value(
    role: usize,
    value: &crate::util::Value,
) -> Option<AcsMetadataEndpoint> {
    let binding = Binding::from_urn(value.get_str("binding")?)?;
    let location = value.get_str("location")?.to_string();
    Some(AcsMetadataEndpoint {
        binding,
        location,
        index: endpoint_index(value),
        is_default: DefaultMarking::from_attribute(value.get_str("isDefault")),
        role,
    })
}

fn endpoint_index(value: &Value) -> Option<u16> {
    value
        .get_str("index")
        .and_then(|index| index.parse::<u16>().ok())
}

fn select_indexed_default<T>(
    endpoints: Vec<T>,
    marking: impl Fn(&T) -> DefaultMarking,
) -> Option<T> {
    if let Some(index) = endpoints
        .iter()
        .position(|endpoint| marking(endpoint) == DefaultMarking::Default)
    {
        return endpoints.into_iter().nth(index);
    }
    if let Some(index) = endpoints
        .iter()
        .position(|endpoint| marking(endpoint) != DefaultMarking::NotDefault)
    {
        return endpoints.into_iter().nth(index);
    }
    endpoints.into_iter().next()
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
                .assertion_consumer_location(Binding::Post)
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
                .assertion_consumer_location(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/second")
        );
        assert_eq!(
            false_then_omitted
                .assertion_consumer_location(Binding::Redirect)
                .as_deref(),
            Some("https://sp.example.com/redirect")
        );

        let all_false = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="0"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="false"/>"#,
        )?;
        assert_eq!(
            all_false
                .assertion_consumer_location(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/first")
        );

        let numeric_true = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="0"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="1"/>"#,
        )?;
        assert_eq!(
            numeric_true
                .assertion_consumer_location(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/second")
        );

        for value in ["false", "0"] {
            let foreign_false = sp_with_acs(&format!(
                r#"<AssertionConsumerService xmlns:ext="urn:example" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" ext:isDefault="{value}"/>
                   <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1"/>"#,
            ))?;
            assert_eq!(
                foreign_false
                    .assertion_consumer_location(Binding::Post)
                    .as_deref(),
                Some("https://sp.example.com/first"),
                "ext:isDefault={value}"
            );
        }

        for attributes in [
            r#"ext:isDefault="false" isDefault="true""#,
            r#"isDefault="true" ext:isDefault="false""#,
        ] {
            let qualified_and_unqualified = sp_with_acs(&format!(
                r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0"/>
                   <AssertionConsumerService xmlns:ext="urn:example" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" {attributes}/>"#,
            ))?;
            assert_eq!(
                qualified_and_unqualified
                    .assertion_consumer_location(Binding::Post)
                    .as_deref(),
                Some("https://sp.example.com/second"),
                "{attributes}"
            );
        }

        for is_default in [
            " true ",
            " 1 ",
            "&#x9;&#xA;&#xD;true&#xD;&#xA;&#x9;",
            "&#x9;&#xA;&#xD;1&#xD;&#xA;&#x9;",
        ] {
            let whitespace_true = sp_with_acs(&format!(
                r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0"/>
                   <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="{is_default}"/>"#,
            ))?;
            assert_eq!(
                whitespace_true
                    .assertion_consumer_location(Binding::Post)
                    .as_deref(),
                Some("https://sp.example.com/second"),
                "isDefault={is_default}"
            );
        }

        for is_default in [
            " false ",
            " 0 ",
            "&#x9;&#xA;&#xD;false&#xD;&#xA;&#x9;",
            "&#x9;&#xA;&#xD;0&#xD;&#xA;&#x9;",
        ] {
            let whitespace_false = sp_with_acs(&format!(
                r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="{is_default}"/>
                   <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1"/>"#,
            ))?;
            assert_eq!(
                whitespace_false
                    .assertion_consumer_location(Binding::Post)
                    .as_deref(),
                Some("https://sp.example.com/second"),
                "isDefault={is_default}"
            );
        }

        let unrecognized = sp_with_acs(
            r#"<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/first" index="0" isDefault="yes"/>
               <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/second" index="1" isDefault="false"/>"#,
        )?;
        assert_eq!(
            unrecognized
                .assertion_consumer_location(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/first")
        );
        Ok(())
    }
}
