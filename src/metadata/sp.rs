use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::util::Value;
use crate::xml::{extract_with_limits, ExtractorField, XmlLimits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcsMetadataEndpoint {
    pub(crate) binding: Binding,
    pub(crate) location: String,
    pub(crate) index: Option<u16>,
    pub(crate) is_default: DefaultMarking,
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
    saml2_assertion_consumer_services: Value,
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
        let limits = policy.limits;
        let extra = vec![
            ExtractorField::new("spRoleContext", &["EntityDescriptor", "SPSSODescriptor"])
                .capture_source(),
            ExtractorField::new(
                "manageNameIDService",
                &["EntityDescriptor", "SPSSODescriptor", "ManageNameIDService"],
            )
            .capture_source(),
            ExtractorField::new(
                "assertionConsumerService",
                &[
                    "EntityDescriptor",
                    "SPSSODescriptor",
                    "AssertionConsumerService",
                ],
            )
            .capture_source(),
        ];
        let mut inner = Metadata::parse_role_with_policy(
            xml,
            super::SsoDescriptorRole::ServiceProvider,
            extra,
            policy,
        )?;
        let role_context = match &mut inner.meta {
            Value::Object(entries) => entries
                .iter()
                .position(|(key, _)| key == "spRoleContext")
                .map(|index| entries.remove(index).1)
                .unwrap_or_default(),
            Value::Null | Value::Str(_) | Value::Array(_) => Value::Null,
        };
        let first_saml2_role = match &role_context {
            Value::Array(roles) => roles.first(),
            Value::Null | Value::Str(_) | Value::Object(_) => Some(&role_context),
        }
        .and_then(Value::as_str)
        .ok_or_else(|| SamlError::MissingMetadata("SPSSODescriptor".into()))?;
        let saml2_assertion_consumer_services = saml2_role_acs(first_saml2_role, limits)?;
        super::endpoints::read_endpoints(
            &mut inner.meta,
            "manageNameIDService",
            &["Binding", "Location", "ResponseLocation"],
        )?;
        super::endpoints::read_endpoints(
            &mut inner.meta,
            "assertionConsumerService",
            &["Binding", "Location", "isDefault", "index"],
        )?;
        Ok(Self {
            inner,
            saml2_assertion_consumer_services,
        })
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
    /// The default is the first endpoint for `binding` with `isDefault` true,
    /// otherwise the first whose `isDefault` is not false, otherwise the first.
    /// `true` and `1` are true. `false` and `0` are false.
    pub fn assertion_consumer_location(&self, binding: Binding) -> Option<String> {
        self.assertion_consumer_service_endpoint(binding)
            .map(|endpoint| endpoint.location)
    }

    pub(crate) fn assertion_consumer_service_endpoint(
        &self,
        binding: Binding,
    ) -> Option<AcsMetadataEndpoint> {
        let endpoints = self
            .assertion_consumer_service_endpoints()
            .into_iter()
            .filter(|endpoint| endpoint.binding == binding)
            .collect();
        select_indexed_default(endpoints, |endpoint| endpoint.is_default)
    }

    pub(crate) fn default_assertion_consumer_service_endpoint(
        &self,
    ) -> Result<Option<AcsMetadataEndpoint>, SamlError> {
        select_indexed_default(
            as_object_list(&self.saml2_assertion_consumer_services),
            |value| DefaultMarking::from_attribute(value.get_str("isDefault")),
        )
        .map(|value| {
            acs_metadata_endpoint_from_value(value).ok_or_else(|| {
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

    pub(crate) fn assertion_consumer_service_locations(&self, binding: Binding) -> Vec<String> {
        self.assertion_consumer_service_endpoints()
            .into_iter()
            .filter(|endpoint| endpoint.binding == binding)
            .map(|endpoint| endpoint.location)
            .collect()
    }

    pub(crate) fn has_assertion_consumer_service(&self, binding: Binding, location: &str) -> bool {
        self.assertion_consumer_service_endpoints()
            .iter()
            .any(|endpoint| endpoint.binding == binding && endpoint.location == location)
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

fn saml2_role_acs(role: &str, limits: XmlLimits) -> Result<Value, SamlError> {
    let field = ExtractorField::new(
        "assertionConsumerService",
        &["SPSSODescriptor", "AssertionConsumerService"],
    )
    .capture_source();
    let extracted = extract_with_limits(role, &[field], limits)?;
    super::endpoints::parse_endpoint_fragments(
        extracted
            .get("assertionConsumerService")
            .unwrap_or(&Value::Null),
        &["Binding", "Location", "isDefault", "index"],
    )
}

fn acs_metadata_endpoint_from_value(value: &crate::util::Value) -> Option<AcsMetadataEndpoint> {
    let binding = Binding::from_urn(value.get_str("binding")?)?;
    let location = value.get_str("location")?.to_string();
    let index = value
        .get_str("index")
        .and_then(|index| index.parse::<u16>().ok());
    Some(AcsMetadataEndpoint {
        binding,
        location,
        index,
        is_default: DefaultMarking::from_attribute(value.get_str("isDefault")),
    })
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
