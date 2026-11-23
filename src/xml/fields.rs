//! SAML message field-sets for XML extraction, and the keys and paths that
//! read the values they extract.
//!
//! A field that reads two or more attributes stores an object whose keys are
//! the camelCased attribute names. A path such as [`request::ID`] reaches one
//! of them.

use super::extract::ExtractorField;

/// Key of the message's own `<Issuer>`.
///
/// [`login_response_fields`] stores the assertion's `<Issuer>` under
/// [`login_response::ASSERTION_ISSUER`] instead.
pub(crate) const ISSUER: &str = "issuer";

/// Key of the message's own `<Signature>` element.
pub(crate) const SIGNATURE: &str = "signature";

/// Paths into the object of a request element's attributes.
pub(crate) mod request {
    pub(crate) const KEY: &str = "request";
    pub(crate) const ID: &str = "request.id";
    pub(crate) const VERSION: &str = "request.version";
    pub(crate) const ISSUE_INSTANT: &str = "request.issueInstant";
    pub(crate) const DESTINATION: &str = "request.destination";
    pub(crate) const ASSERTION_CONSUMER_SERVICE_URL: &str = "request.assertionConsumerServiceUrl";
    pub(crate) const PROTOCOL_BINDING: &str = "request.protocolBinding";
    pub(crate) const ASSERTION_CONSUMER_SERVICE_INDEX: &str =
        "request.assertionConsumerServiceIndex";
    pub(crate) const FORCE_AUTHN: &str = "request.forceAuthn";
    pub(crate) const IS_PASSIVE: &str = "request.isPassive";
    pub(crate) const PROVIDER_NAME: &str = "request.providerName";
    pub(crate) const NOT_ON_OR_AFTER: &str = "request.notOnOrAfter";
}

/// Paths into the object of a response element's attributes.
pub(crate) mod response {
    pub(crate) const KEY: &str = "response";
    pub(crate) const ID: &str = "response.id";
    pub(crate) const ISSUE_INSTANT: &str = "response.issueInstant";
    pub(crate) const DESTINATION: &str = "response.destination";
    pub(crate) const IN_RESPONSE_TO: &str = "response.inResponseTo";
}

/// Keys and paths of the `<NameID>` in a login response or logout request.
pub(crate) mod name_id {
    pub(crate) const VALUE: &str = "nameID";
    pub(crate) const FORMAT: &str = "nameIDFormat";
    pub(crate) const QUALIFIERS: &str = "nameIDQualifiers";
    pub(crate) const NAME_QUALIFIER: &str = "nameIDQualifiers.nameQualifier";
    pub(crate) const SP_NAME_QUALIFIER: &str = "nameIDQualifiers.spNameQualifier";
    pub(crate) const SP_PROVIDED_ID: &str = "nameIDQualifiers.spProvidedId";
}

/// Keys and paths that only [`login_request_fields`] extracts.
pub(crate) mod authn_request {
    pub(crate) const NAME_ID_POLICY: &str = "nameIDPolicy";
    pub(crate) const NAME_ID_POLICY_FORMAT: &str = "nameIDPolicy.format";
    pub(crate) const NAME_ID_POLICY_SP_NAME_QUALIFIER: &str = "nameIDPolicy.spNameQualifier";
    pub(crate) const NAME_ID_POLICY_ALLOW_CREATE: &str = "nameIDPolicy.allowCreate";
    pub(crate) const REQUESTED_SUBJECT: &str = "requestedSubject";
    pub(crate) const REQUESTED_NAME_ID: &str = "requestedNameId";
    pub(crate) const REQUESTED_NAME_ID_FORMAT: &str = "requestedNameIdFormat";
    pub(crate) const REQUESTED_NAME_QUALIFIER: &str = "requestedNameQualifier";
    pub(crate) const REQUESTED_SP_NAME_QUALIFIER: &str = "requestedSpNameQualifier";
    pub(crate) const REQUESTED_SP_PROVIDED_ID: &str = "requestedSpProvidedId";
    pub(crate) const REQUESTED_BASE_ID: &str = "requestedBaseId";
    pub(crate) const REQUESTED_ENCRYPTED_ID: &str = "requestedEncryptedId";
    pub(crate) const REQUESTED_SUBJECT_CONFIRMATION: &str = "requestedSubjectConfirmation";
    pub(crate) const REQUESTED_AUTHN_CONTEXT: &str = "requestedAuthnContext";
    pub(crate) const REQUESTED_AUTHN_CONTEXT_COMPARISON: &str = "requestedAuthnContextComparison";
    pub(crate) const AUTHN_CONTEXT_CLASS_REF: &str = "authnContextClassRef";
    pub(crate) const AUTHN_CONTEXT_DECL_REF: &str = "authnContextDeclRef";
}

/// Keys and paths that only [`login_response_fields`] extracts.
pub(crate) mod login_response {
    pub(crate) const ASSERTION: &str = "assertion";
    pub(crate) const ASSERTION_ID: &str = "assertion.id";
    pub(crate) const ASSERTION_ISSUE_INSTANT: &str = "assertion.issueInstant";
    pub(crate) const ASSERTION_ISSUER: &str = "issuer";
    /// The [`super::conditions`] object of the assertion `<Conditions>`.
    pub(crate) const CONDITIONS: &str = "conditions";
    pub(crate) const AUDIENCE: &str = "audience";
    pub(crate) const AUDIENCE_RESTRICTION: &str = "audienceRestriction";
    pub(crate) const SUBJECT_CONFIRMATION: &str = "subjectConfirmation";
    /// One [`super::authn_statement`] object per `<AuthnStatement>`.
    pub(crate) const AUTHN_STATEMENTS: &str = "sessionIndex";
    pub(crate) const ATTRIBUTES: &str = "attributes";
    /// One [`super::attribute`] object per `<Attribute>`.
    pub(crate) const ATTRIBUTE_ELEMENTS: &str = "attributeNameFormats";
}

/// Keys of the object under [`login_response::CONDITIONS`].
pub(crate) mod conditions {
    pub(crate) const NOT_BEFORE: &str = "notBefore";
    pub(crate) const NOT_ON_OR_AFTER: &str = "notOnOrAfter";
}

/// Keys of each object under [`login_response::AUTHN_STATEMENTS`].
pub(crate) mod authn_statement {
    pub(crate) const AUTHN_INSTANT: &str = "authnInstant";
    pub(crate) const SESSION_NOT_ON_OR_AFTER: &str = "sessionNotOnOrAfter";
    pub(crate) const SESSION_INDEX: &str = "sessionIndex";
}

/// Keys of each object under [`login_response::ATTRIBUTE_ELEMENTS`].
pub(crate) mod attribute {
    pub(crate) const NAME: &str = "name";
    pub(crate) const NAME_FORMAT: &str = "nameFormat";
    pub(crate) const FRIENDLY_NAME: &str = "friendlyName";
    pub(crate) const VALUES: &str = "attributeValue";
}

/// Keys that only [`logout_request_fields`] extracts.
pub(crate) mod logout_request {
    /// The text of each `<SessionIndex>`.
    pub(crate) const SESSION_INDEXES: &str = "sessionIndex";
}

/// Keys that only [`logout_response_fields`] extracts.
pub(crate) mod logout_response {
    pub(crate) const STATUS_CODE: &str = "statusCode";
    pub(crate) const SUBORDINATE_STATUS_CODE: &str = "subordinateStatusCode";
}

/// Keys of the two-tier status field sets.
pub(crate) mod status {
    pub(crate) const TOP: &str = "top";
    pub(crate) const SECOND: &str = "second";
}

/// Fields for an `<AuthnRequest>` (`loginRequestFields`).
pub fn login_request_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(request::KEY, &["AuthnRequest"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "AssertionConsumerServiceURL",
            "ProtocolBinding",
            "AssertionConsumerServiceIndex",
            "ForceAuthn",
            "IsPassive",
            "ProviderName",
        ]),
        ExtractorField::new(ISSUER, &["AuthnRequest", "Issuer"]),
        ExtractorField::new(
            authn_request::NAME_ID_POLICY,
            &["AuthnRequest", "NameIDPolicy"],
        )
        .attrs(&["Format", "SPNameQualifier", "AllowCreate"]),
        ExtractorField::new(
            authn_request::REQUESTED_SUBJECT,
            &["AuthnRequest", "Subject"],
        )
        .with_context(),
        ExtractorField::new(
            authn_request::REQUESTED_NAME_ID,
            &["AuthnRequest", "Subject", "NameID"],
        ),
        ExtractorField::new(
            authn_request::REQUESTED_NAME_ID_FORMAT,
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["Format"]),
        ExtractorField::new(
            authn_request::REQUESTED_NAME_QUALIFIER,
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["NameQualifier"]),
        ExtractorField::new(
            authn_request::REQUESTED_SP_NAME_QUALIFIER,
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["SPNameQualifier"]),
        ExtractorField::new(
            authn_request::REQUESTED_SP_PROVIDED_ID,
            &["AuthnRequest", "Subject", "NameID"],
        )
        .attrs(&["SPProvidedID"]),
        ExtractorField::new(
            authn_request::REQUESTED_BASE_ID,
            &["AuthnRequest", "Subject", "BaseID"],
        )
        .with_context(),
        ExtractorField::new(
            authn_request::REQUESTED_ENCRYPTED_ID,
            &["AuthnRequest", "Subject", "EncryptedID"],
        )
        .with_context(),
        ExtractorField::new(
            authn_request::REQUESTED_SUBJECT_CONFIRMATION,
            &["AuthnRequest", "Subject", "SubjectConfirmation"],
        )
        .with_context(),
        ExtractorField::new(
            authn_request::REQUESTED_AUTHN_CONTEXT,
            &["AuthnRequest", "RequestedAuthnContext"],
        )
        .with_context(),
        ExtractorField::new(
            authn_request::REQUESTED_AUTHN_CONTEXT_COMPARISON,
            &["AuthnRequest", "RequestedAuthnContext"],
        )
        .attrs(&["Comparison"]),
        ExtractorField::new(
            authn_request::AUTHN_CONTEXT_CLASS_REF,
            &[
                "AuthnRequest",
                "RequestedAuthnContext",
                "AuthnContextClassRef",
            ],
        ),
        ExtractorField::new(
            authn_request::AUTHN_CONTEXT_DECL_REF,
            &[
                "AuthnRequest",
                "RequestedAuthnContext",
                "AuthnContextDeclRef",
            ],
        ),
        ExtractorField::new(SIGNATURE, &["AuthnRequest", "Signature"]).with_context(),
    ]
}

/// Two-tier status fields for a `<Response>` (`loginResponseStatusFields`).
pub fn login_response_status_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(status::TOP, &["Response", "Status", "StatusCode"]).attrs(&["Value"]),
        ExtractorField::new(
            status::SECOND,
            &["Response", "Status", "StatusCode", "StatusCode"],
        )
        .attrs(&["Value"]),
    ]
}

/// Two-tier status fields for a `<LogoutResponse>` (`logoutResponseStatusFields`).
pub fn logout_response_status_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(status::TOP, &["LogoutResponse", "Status", "StatusCode"])
            .attrs(&["Value"]),
        ExtractorField::new(
            status::SECOND,
            &["LogoutResponse", "Status", "StatusCode", "StatusCode"],
        )
        .attrs(&["Value"]),
    ]
}

/// Fields for a login `<Response>` whose status is not `Success`.
pub(crate) fn login_error_response_fields() -> Vec<ExtractorField> {
    vec![ExtractorField::new(response::KEY, &["Response"]).attrs(&["Destination", "InResponseTo"])]
}

/// Fields for a login `<Response>` (`loginResponseFields`).
///
/// `assertion` is the (verified) assertion XML used as the `shortcut` document
/// for assertion-scoped fields; `response` is read from the full message.
pub fn login_response_fields(assertion: &str) -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(login_response::ASSERTION, &["Assertion"])
            .attrs(&["ID", "IssueInstant"])
            .with_shortcut(assertion),
        ExtractorField::new(login_response::CONDITIONS, &["Assertion", "Conditions"])
            .attrs(&["NotBefore", "NotOnOrAfter"])
            .with_shortcut(assertion),
        ExtractorField::new(response::KEY, &["Response"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "InResponseTo",
        ]),
        ExtractorField::new(
            login_response::AUDIENCE,
            &["Assertion", "Conditions", "AudienceRestriction", "Audience"],
        )
        .with_shortcut(assertion),
        ExtractorField::new(
            login_response::AUDIENCE_RESTRICTION,
            &["Assertion", "Conditions", "AudienceRestriction"],
        )
        .with_context()
        .with_shortcut(assertion),
        ExtractorField::new(login_response::ASSERTION_ISSUER, &["Assertion", "Issuer"])
            .with_shortcut(assertion),
        ExtractorField::new(name_id::VALUE, &["Assertion", "Subject", "NameID"])
            .with_shortcut(assertion),
        ExtractorField::new(name_id::FORMAT, &["Assertion", "Subject", "NameID"])
            .attrs(&["Format"])
            .with_shortcut(assertion),
        ExtractorField::new(name_id::QUALIFIERS, &["Assertion", "Subject", "NameID"])
            .attrs(&["NameQualifier", "SPNameQualifier", "SPProvidedID"])
            .with_shortcut(assertion),
        ExtractorField::new(
            login_response::SUBJECT_CONFIRMATION,
            &["Assertion", "Subject", "SubjectConfirmation"],
        )
        .with_context()
        .with_shortcut(assertion),
        ExtractorField::new(
            login_response::AUTHN_STATEMENTS,
            &["Assertion", "AuthnStatement"],
        )
        .attrs(&["AuthnInstant", "SessionNotOnOrAfter", "SessionIndex"])
        .with_shortcut(assertion),
        ExtractorField::new(
            login_response::ATTRIBUTES,
            &["Assertion", "AttributeStatement", "Attribute"],
        )
        .aggregate(&["Name"], &["AttributeValue"])
        .with_shortcut(assertion),
        ExtractorField::new(
            login_response::ATTRIBUTE_ELEMENTS,
            &["Assertion", "AttributeStatement", "Attribute"],
        )
        .attrs(&["Name", "NameFormat", "FriendlyName"])
        .child_texts(&["AttributeValue"])
        .with_shortcut(assertion),
    ]
}

/// Fields for a `<LogoutRequest>` (`logoutRequestFields`).
pub fn logout_request_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(request::KEY, &["LogoutRequest"]).attrs(&[
            "ID",
            "Version",
            "IssueInstant",
            "Destination",
            "NotOnOrAfter",
        ]),
        ExtractorField::new(ISSUER, &["LogoutRequest", "Issuer"]),
        ExtractorField::new(name_id::VALUE, &["LogoutRequest", "NameID"]),
        ExtractorField::new(name_id::FORMAT, &["LogoutRequest", "NameID"]).attrs(&["Format"]),
        ExtractorField::new(name_id::QUALIFIERS, &["LogoutRequest", "NameID"]).attrs(&[
            "NameQualifier",
            "SPNameQualifier",
            "SPProvidedID",
        ]),
        ExtractorField::new(
            logout_request::SESSION_INDEXES,
            &["LogoutRequest", "SessionIndex"],
        ),
        ExtractorField::new(SIGNATURE, &["LogoutRequest", "Signature"]).with_context(),
    ]
}

/// Fields for a `<ManageNameIDRequest>`.
pub(crate) fn manage_name_id_request_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(request::KEY, &["ManageNameIDRequest"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
        ]),
        ExtractorField::new(ISSUER, &["ManageNameIDRequest", "Issuer"]),
    ]
}

/// Fields for a `<ManageNameIDResponse>`.
pub(crate) fn manage_name_id_response_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(response::KEY, &["ManageNameIDResponse"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "InResponseTo",
        ]),
        ExtractorField::new(ISSUER, &["ManageNameIDResponse", "Issuer"]),
    ]
}

/// Two-tier status fields for a `<ManageNameIDResponse>`.
pub(crate) fn manage_name_id_response_status_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(
            status::TOP,
            &["ManageNameIDResponse", "Status", "StatusCode"],
        )
        .attrs(&["Value"]),
        ExtractorField::new(
            status::SECOND,
            &["ManageNameIDResponse", "Status", "StatusCode", "StatusCode"],
        )
        .attrs(&["Value"]),
    ]
}

/// Fields for a `<LogoutResponse>` (`logoutResponseFields`).
pub fn logout_response_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new(response::KEY, &["LogoutResponse"]).attrs(&[
            "ID",
            "IssueInstant",
            "Destination",
            "InResponseTo",
        ]),
        ExtractorField::new(ISSUER, &["LogoutResponse", "Issuer"]),
        ExtractorField::new(
            logout_response::STATUS_CODE,
            &["LogoutResponse", "Status", "StatusCode"],
        )
        .attrs(&["Value"]),
        ExtractorField::new(
            logout_response::SUBORDINATE_STATUS_CODE,
            &["LogoutResponse", "Status", "StatusCode", "StatusCode"],
        )
        .attrs(&["Value"]),
        ExtractorField::new(SIGNATURE, &["LogoutResponse", "Signature"]).with_context(),
    ]
}
