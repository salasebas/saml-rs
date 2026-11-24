use std::collections::HashSet;
use std::time::SystemTime;

use crate::xml::dom::is_xml_whitespace_char;
use crate::{Attribute, AttributeValue, EntityId, IdpDescriptor, SamlError, SsoSession};

/// The source of literal scopes authorized for one assertion issuer.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum AttributeScopePolicy<'a> {
    /// Scopes configured by the service provider for a particular issuer.
    Explicit {
        /// The issuer allowed to assert the scopes.
        issuer: &'a EntityId,
        /// The issuer's allowed literal scopes, compared case-sensitively.
        scopes: &'a [&'a str],
    },
    /// Literal scopes from metadata signed by a trusted registration authority.
    RegistrationAuthority {
        /// The issuer's descriptor imported with
        /// [`MetadataTrustPolicy::RequireRegistrationAuthoritySignature`](crate::MetadataTrustPolicy::RequireRegistrationAuthoritySignature).
        idp: &'a IdpDescriptor,
        /// The time at which to check the metadata's validity.
        now: SystemTime,
    },
}

/// A value that failed a scope check on an accepted SSO session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScopedAttributeViolation<'a> {
    /// The attribute that carried the value.
    pub attribute: &'a Attribute,
    /// The assertion value as exposed in the session.
    pub value: &'a AttributeValue,
    /// The unauthorized scope, or `None` when the value is not `value@scope`.
    pub scope: Option<&'a str>,
}

impl SsoSession {
    /// Report values of the named attributes whose scopes the issuer cannot assert.
    ///
    /// Selects attributes by exact SAML `Name`, across all `NameFormat` values.
    /// A value must contain exactly one `@` with a nonempty part on each side,
    /// after removing leading and trailing XML whitespace. Literal scopes
    /// compare case-sensitively. Regular expression declarations are ignored.
    ///
    /// The returned violations follow session attribute and value order. Missing
    /// attributes produce no violations. Use this check before consuming scoped
    /// values, for example before an account lookup. The session is unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] if the policy names a different issuer,
    /// the metadata lacks a verified registration authority signature, or a
    /// scope declaration is malformed. Returns [`SamlError::TimeWindowInvalid`]
    /// if the authority's metadata has expired at the supplied time.
    pub fn scoped_attribute_violations(
        &self,
        attribute_names: &[&str],
        policy: AttributeScopePolicy<'_>,
    ) -> Result<Vec<ScopedAttributeViolation<'_>>, SamlError> {
        let issuer = match policy {
            AttributeScopePolicy::Explicit { issuer, .. } => issuer,
            AttributeScopePolicy::RegistrationAuthority { idp, .. } => idp.entity_id(),
        };
        if issuer != self.issuer() {
            return Err(SamlError::Invalid(
                "scope policy issuer did not match the assertion issuer".into(),
            ));
        }

        let metadata_scopes;
        let allowed: HashSet<&str> = match policy {
            AttributeScopePolicy::Explicit { scopes, .. } => scopes.iter().copied().collect(),
            AttributeScopePolicy::RegistrationAuthority { idp, now } => {
                metadata_scopes = idp.registration_authority_scopes(now)?;
                metadata_scopes
                    .iter()
                    .filter(|scope| !scope.regexp)
                    .map(|scope| scope.value.as_str())
                    .collect()
            }
        };
        let mut violations = Vec::new();
        for attribute in self
            .attributes()
            .iter()
            .filter(|a| attribute_names.contains(&a.name()))
        {
            for value in attribute.values() {
                let scope = value
                    .as_str()
                    .trim_matches(is_xml_whitespace_char)
                    .split_once('@')
                    .filter(|(local, scope)| {
                        !local.is_empty() && !scope.is_empty() && !scope.contains('@')
                    })
                    .map(|(_, scope)| scope);
                if !scope.is_some_and(|scope| allowed.contains(scope)) {
                    violations.push(ScopedAttributeViolation {
                        attribute,
                        value,
                        scope,
                    });
                }
            }
        }
        Ok(violations)
    }
}
