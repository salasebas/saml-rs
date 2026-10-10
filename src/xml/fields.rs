//! SAML message field-sets for XML extraction.

use super::extract::ExtractorField;

/// Fields for an `<AuthnRequest>` (`loginRequestFields`).
pub fn login_request_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("request", &["AuthnRequest"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "AssertionConsumerServiceURL",
            "ProtocolBinding",
            "AssertionConsumerServiceIndex",
            "ForceAuthn",
            "IsPassive",
        ]),
        ExtractorField::new("issuer", &["AuthnRequest", "Issuer"]),
        ExtractorField::new("nameIDPolicy", &["AuthnRequest", "NameIDPolicy"])
            .attrs(&["Format", "AllowCreate"]),
        ExtractorField::new("requestedSubject", &["AuthnRequest", "Subject"]).with_context(),
        ExtractorField::new("requestedNameId", &["AuthnRequest", "Subject", "NameID"]),
        ExtractorField::new(
            "requestedNameIdFormat",
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["Format"]),
        ExtractorField::new(
            "requestedNameQualifier",
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["NameQualifier"]),
        ExtractorField::new(
            "requestedSpNameQualifier",
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["SPNameQualifier"]),
        ExtractorField::new(
            "requestedSpProvidedId",
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["SPProvidedID"]),
        ExtractorField::new("requestedBaseId", &["AuthnRequest", "Subject", "BaseID"])
            .with_context(),
        ExtractorField::new(
            "requestedEncryptedId",
            &["AuthnRequest", "Subject", "EncryptedID"],
        )
        .with_context(),
        ExtractorField::new(
            "requestedSubjectConfirmation",
            &["AuthnRequest", "Subject", "SubjectConfirmation"],
        )
        .with_context(),
        ExtractorField::new(
            "authnContextClassRef",
            &["AuthnRequest", "AuthnContextClassRef"],
        ),
        ExtractorField::new("signature", &["AuthnRequest", "Signature"]).with_context(),
    ]
}

/// Two-tier status fields for a `<Response>` (`loginResponseStatusFields`).
pub fn login_response_status_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("top", &["Response", "Status", "StatusCode"]).attrs(&["Value"]),
        ExtractorField::new(
            "second",
            &["Response", "Status", "StatusCode", "StatusCode"],
        )
        .attrs(&["Value"]),
    ]
}

/// Two-tier status fields for a `<LogoutResponse>` (`logoutResponseStatusFields`).
pub fn logout_response_status_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("top", &["LogoutResponse", "Status", "StatusCode"]).attrs(&["Value"]),
        ExtractorField::new(
            "second",
            &["LogoutResponse", "Status", "StatusCode", "StatusCode"],
        )
        .attrs(&["Value"]),
    ]
}

/// Fields for a login `<Response>` (`loginResponseFields`).
///
/// `assertion` is the (verified) assertion XML used as the `shortcut` document
/// for assertion-scoped fields; `response` is read from the full message.
pub fn login_response_fields(assertion: &str) -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("assertion", &["Assertion"])
            .attrs(&["ID", "IssueInstant"])
            .with_shortcut(assertion),
        ExtractorField::new("conditions", &["Assertion", "Conditions"])
            .attrs(&["NotBefore", "NotOnOrAfter"])
            .with_shortcut(assertion),
        ExtractorField::new("response", &["Response"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "InResponseTo",
        ]),
        ExtractorField::new(
            "audience",
            &["Assertion", "Conditions", "AudienceRestriction", "Audience"],
        )
        .with_shortcut(assertion),
        ExtractorField::new("issuer", &["Assertion", "Issuer"]).with_shortcut(assertion),
        ExtractorField::new("nameID", &["Assertion", "Subject", "NameID"]).with_shortcut(assertion),
        ExtractorField::new("nameIDFormat", &["Assertion", "Subject", "NameID"])
            .attrs(&["Format"])
            .with_shortcut(assertion),
        ExtractorField::new(
            "subjectConfirmation",
            &["Assertion", "Subject", "SubjectConfirmation"],
        )
        .with_context()
        .with_shortcut(assertion),
        ExtractorField::new("sessionIndex", &["Assertion", "AuthnStatement"])
            .attrs(&["AuthnInstant", "SessionNotOnOrAfter", "SessionIndex"])
            .with_shortcut(assertion),
        ExtractorField::new(
            "attributes",
            &["Assertion", "AttributeStatement", "Attribute"],
        )
        .aggregate(&["Name"], &["AttributeValue"])
        .with_shortcut(assertion),
    ]
}

/// Fields for a `<LogoutRequest>` (`logoutRequestFields`).
pub fn logout_request_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("request", &["LogoutRequest"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "NotOnOrAfter",
        ]),
        ExtractorField::new("issuer", &["LogoutRequest", "Issuer"]),
        ExtractorField::new("nameID", &["LogoutRequest", "NameID"]),
        ExtractorField::new("nameIDFormat", &["LogoutRequest", "NameID"]).attrs(&["Format"]),
        ExtractorField::new("nameQualifier", &["LogoutRequest", "NameID"])
            .attrs(&["NameQualifier"]),
        ExtractorField::new("spNameQualifier", &["LogoutRequest", "NameID"])
            .attrs(&["SPNameQualifier"]),
        ExtractorField::new("spProvidedId", &["LogoutRequest", "NameID"]).attrs(&["SPProvidedID"]),
        ExtractorField::new("sessionIndex", &["LogoutRequest", "SessionIndex"]),
        ExtractorField::new("signature", &["LogoutRequest", "Signature"]).with_context(),
    ]
}

/// Fields for a `<LogoutResponse>` (`logoutResponseFields`).
pub fn logout_response_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("response", &["LogoutResponse"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "InResponseTo",
        ]),
        ExtractorField::new("issuer", &["LogoutResponse", "Issuer"]),
        ExtractorField::new("signature", &["LogoutResponse", "Signature"]).with_context(),
    ]
}
