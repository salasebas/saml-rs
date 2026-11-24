//! SAML 2.0 URN constants and keywords.
//!
//! String values follow the SAML and XML-DSig/XML-Enc specifications so
//! messages and metadata interoperate.

/// Default maximum estimated decryption work per inbound message.
///
/// Counts XML Encryption `EncryptedData`, `EncryptedKey`, and `DerivedKey`
/// elements, multiplied by the number of configured local decryption keys.
/// Newly revealed encrypted content shares the allowance. This estimates
/// possible key-resolution attempts; it does not measure CPU time.
pub const DEFAULT_MAX_DECRYPTION_WORK: usize = 16;

/// Protocol binding.
///
/// Combines full binding URNs and short binding keywords in one type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Binding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
    /// HTTP-Artifact binding. The typed API delivers a Web SSO `<Response>`
    /// with it.
    Artifact,
    /// SOAP binding for a synchronous request and response. The typed API
    /// sends Single Logout with it.
    Soap,
}

impl Binding {
    /// Full binding URN.
    pub const fn urn(self) -> &'static str {
        match self {
            Binding::Redirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Binding::Post => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Binding::SimpleSign => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign",
            Binding::Artifact => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            Binding::Soap => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        }
    }

    /// Short binding keyword.
    pub fn short_name(self) -> &'static str {
        match self {
            Binding::Redirect => "redirect",
            Binding::Post => "post",
            Binding::SimpleSign => "simpleSign",
            Binding::Artifact => "artifact",
            Binding::Soap => "soap",
        }
    }

    /// Resolve from a short keyword (`redirect`, `post`, `simpleSign`,
    /// `artifact`, `soap`).
    pub fn from_short_name(name: &str) -> Option<Self> {
        match name {
            "redirect" => Some(Binding::Redirect),
            "post" => Some(Binding::Post),
            "simpleSign" => Some(Binding::SimpleSign),
            "artifact" => Some(Binding::Artifact),
            "soap" => Some(Binding::Soap),
            _ => None,
        }
    }

    /// Resolve from a full binding URN.
    pub fn from_urn(urn: &str) -> Option<Self> {
        [
            Binding::Redirect,
            Binding::Post,
            Binding::SimpleSign,
            Binding::Artifact,
            Binding::Soap,
        ]
        .into_iter()
        .find(|b| b.urn() == urn)
    }
}

/// XML namespace URIs used in SAML documents.
pub mod namespace {
    /// SAML 2.0 protocol namespace.
    pub const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    /// SAML 2.0 assertion namespace.
    pub const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    /// SAML 2.0 metadata namespace.
    pub const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
    /// XML-DSig namespace.
    pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
}

/// SAML NameID format URIs.
pub mod name_id_format {
    /// Email address format.
    pub const EMAIL_ADDRESS: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    /// Persistent identifier format.
    pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    /// Transient identifier format.
    pub const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    /// Entity identifier format.
    pub const ENTITY: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    /// Unspecified format.
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    /// Kerberos principal name format.
    pub const KERBEROS: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
    /// Windows domain qualified name format.
    pub const WINDOWS_DOMAIN_QUALIFIED_NAME: &str =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
    /// X.509 subject name format.
    pub const X509_SUBJECT_NAME: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
}

/// Attribute name formats (`NameFormat` on `<Attribute>`).
pub mod attribute_name_format {
    /// Unspecified format.
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
    /// URI reference format.
    pub const URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    /// Basic format.
    pub const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
}

/// `Name`s of the entity attributes that metadata publishes in
/// `mdattr:EntityAttributes`.
///
/// Publish each one with [`attribute_name_format::URI`].
pub mod entity_attribute {
    /// Entity categories the entity belongs to. Each value is a category URI.
    pub const ENTITY_CATEGORY: &str = "http://macedir.org/entity-category";
    /// Entity categories whose peers the entity supports. Each value is a
    /// category URI.
    pub const ENTITY_CATEGORY_SUPPORT: &str = "http://macedir.org/entity-category-support";
    /// Assurance frameworks the identity provider is certified under, such as
    /// `https://refeds.org/sirtfi`. Each value is a framework URI.
    pub const ASSURANCE_CERTIFICATION: &str =
        "urn:oasis:names:tc:SAML:attribute:assurance-certification";
    /// Subject identifier a relying party requires. See
    /// [`SubjectIdRequirement`](crate::SubjectIdRequirement).
    pub const SUBJECT_ID_REQUIREMENT: &str = "urn:oasis:names:tc:SAML:profiles:subject-id:req";
}

/// `Name`s of the assertion attributes that identify the subject.
///
/// Send each one with [`attribute_name_format::URI`].
pub mod attribute_name {
    /// The general purpose subject identifier, [`crate::SubjectId`].
    pub const SUBJECT_ID: &str = "urn:oasis:names:tc:SAML:attribute:subject-id";
    /// The pairwise subject identifier, [`crate::PairwiseId`].
    pub const PAIRWISE_ID: &str = "urn:oasis:names:tc:SAML:attribute:pairwise-id";
}

/// SAML authentication context class reference URIs.
pub mod authn_context_class_ref {
    /// Unspecified class.
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
    /// Password class.
    pub const PASSWORD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
    /// Password-protected transport class.
    pub const PASSWORD_PROTECTED_TRANSPORT: &str =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
}

/// SAML status codes (`StatusCode`), top- and second-tier.
pub mod status_code {
    /// Success.
    pub const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    /// Requester error.
    pub const REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
    /// Responder error.
    pub const RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    /// Version mismatch.
    pub const VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
    /// Authentication failed.
    pub const AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
    /// Invalid attribute name or value.
    pub const INVALID_ATTR_NAME_OR_VALUE: &str =
        "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
    /// Invalid NameID policy.
    pub const INVALID_NAME_ID_POLICY: &str =
        "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
    /// No authn context.
    pub const NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
    /// No available IdP.
    pub const NO_AVAILABLE_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";
    /// No passive authentication possible.
    pub const NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
    /// No supported IdP.
    pub const NO_SUPPORTED_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";
    /// Partial logout.
    pub const PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
    /// Proxy count exceeded.
    pub const PROXY_COUNT_EXCEEDED: &str = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";
    /// Request denied.
    pub const REQUEST_DENIED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
    /// Request unsupported.
    pub const REQUEST_UNSUPPORTED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
    /// Request version deprecated.
    pub const REQUEST_VERSION_DEPRECATED: &str =
        "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";
    /// Request version too high.
    pub const REQUEST_VERSION_TOO_HIGH: &str =
        "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";
    /// Request version too low.
    pub const REQUEST_VERSION_TOO_LOW: &str =
        "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";
    /// Resource not recognized.
    pub const RESOURCE_NOT_RECOGNIZED: &str =
        "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";
    /// Too many responses.
    pub const TOO_MANY_RESPONSES: &str = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";
    /// Unknown attribute profile.
    pub const UNKNOWN_ATTR_PROFILE: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";
    /// Unknown principal.
    pub const UNKNOWN_PRINCIPAL: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
    /// Unsupported binding.
    pub const UNSUPPORTED_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
}

/// XML signature algorithm URIs.
pub mod signature_algorithm {
    /// RSA-SHA1.
    pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    /// DSA-SHA1.
    pub const DSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
    /// HMAC-SHA1.
    pub const HMAC_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    /// RSA-SHA256.
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    /// RSASSA-PSS with SHA-256 and MGF1.
    pub const RSA_SHA256_MGF1: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    /// RSA-SHA384.
    pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    /// RSA-SHA512.
    pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
}

/// XML digest algorithm URIs.
pub mod digest_algorithm {
    /// SHA1 digest.
    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
    /// SHA256 digest.
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    /// SHA384 digest.
    pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    /// SHA512 digest.
    pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
}

/// Map a signature algorithm URI to its digest algorithm URI.
pub fn digest_for_signature(sig_alg: &str) -> Option<&'static str> {
    match sig_alg {
        signature_algorithm::RSA_SHA1
        | signature_algorithm::DSA_SHA1
        | signature_algorithm::HMAC_SHA1 => Some(digest_algorithm::SHA1),
        signature_algorithm::RSA_SHA256 => Some(digest_algorithm::SHA256),
        signature_algorithm::RSA_SHA256_MGF1 => Some(digest_algorithm::SHA256),
        signature_algorithm::RSA_SHA384 => Some(digest_algorithm::SHA384),
        signature_algorithm::RSA_SHA512 => Some(digest_algorithm::SHA512),
        _ => None,
    }
}

/// XML data encryption algorithm URIs.
///
/// Algorithm support depends on the configured crypto provider and features.
pub mod data_encryption_algorithm {
    /// AES-128-CBC.
    pub const AES_128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    /// AES-256-CBC.
    pub const AES_256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    /// Triple DES CBC.
    pub const TRIPLE_DES_CBC: &str = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
    /// AES-128-GCM.
    pub const AES_128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    /// AES-256-GCM.
    pub const AES_256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

    /// Alias for [`AES_128_CBC`].
    pub const AES_128: &str = AES_128_CBC;
    /// Alias for [`AES_256_CBC`].
    pub const AES_256: &str = AES_256_CBC;
    /// Alias for [`TRIPLE_DES_CBC`].
    pub const TRIPLE_DES: &str = TRIPLE_DES_CBC;
}

#[cfg(crypto)]
pub(crate) fn is_xml_encryption_gcm_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        data_encryption_algorithm::AES_128_GCM
            | "http://www.w3.org/2009/xmlenc11#aes192-gcm"
            | data_encryption_algorithm::AES_256_GCM
    )
}

pub(crate) fn is_xml_encryption_cbc_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        data_encryption_algorithm::AES_128_CBC
            | "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
            | data_encryption_algorithm::AES_256_CBC
            | data_encryption_algorithm::TRIPLE_DES_CBC
    )
}

/// XML key encryption algorithm URIs.
pub mod key_encryption_algorithm {
    /// RSA-OAEP-MGF1P.
    pub const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    /// XML Encryption 1.1 RSA-OAEP.
    pub const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    /// RSA 1.5.
    pub const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
}

/// XML-DSig transform / canonicalization algorithm URIs.
pub mod transform_algorithm {
    /// Enveloped-signature transform.
    pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    /// Canonical XML 1.0, omitting comments.
    pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /// Exclusive XML canonicalization (also the canonicalization method).
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    /// Exclusive XML canonicalization, retaining comments.
    pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
}

pub(crate) mod url_params {
    /// `SAMLRequest` parameter.
    pub const SAML_REQUEST: &str = "SAMLRequest";
    /// `SAMLResponse` parameter.
    pub const SAML_RESPONSE: &str = "SAMLResponse";
    /// `SigAlg` parameter.
    pub const SIG_ALG: &str = "SigAlg";
    /// `Signature` parameter.
    pub const SIGNATURE: &str = "Signature";
    /// `RelayState` parameter.
    pub const RELAY_STATE: &str = "RelayState";
    /// `SAMLart` parameter.
    pub const SAML_ART: &str = "SAMLart";
}

/// Certificate use in SAML metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUse {
    /// Signing certificate.
    Signing,
    /// Encryption certificate.
    Encryption,
}

impl CertUse {
    /// Metadata keyword (`signing` / `encryption`).
    pub fn as_str(self) -> &'static str {
        match self {
            CertUse::Signing => "signing",
            CertUse::Encryption => "encryption",
        }
    }
}

/// SAML message type used when parsing a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParserType {
    /// `<AuthnRequest>`.
    SamlRequest,
    /// `<Response>`.
    SamlResponse,
    /// `<LogoutRequest>`.
    LogoutRequest,
    /// `<LogoutResponse>`.
    LogoutResponse,
    /// `<ManageNameIDRequest>`.
    ManageNameIdRequest,
    /// `<ManageNameIDResponse>`.
    ManageNameIdResponse,
}

impl ParserType {
    /// Return `SAMLRequest` for requests and `SAMLResponse` for responses.
    pub fn query_param(self) -> &'static str {
        match self {
            ParserType::SamlRequest
            | ParserType::LogoutRequest
            | ParserType::ManageNameIdRequest => url_params::SAML_REQUEST,
            ParserType::SamlResponse
            | ParserType::LogoutResponse
            | ParserType::ManageNameIdResponse => url_params::SAML_RESPONSE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_urns_match_saml_spec_values() {
        assert_eq!(
            Binding::Redirect.urn(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        );
        assert_eq!(
            Binding::Post.urn(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        );
        assert_eq!(
            Binding::SimpleSign.urn(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        );
        assert_eq!(
            Binding::Artifact.urn(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
        );
        assert_eq!(
            Binding::Soap.urn(),
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
        );
    }

    #[test]
    fn binding_short_name_round_trip() {
        for b in [
            Binding::Redirect,
            Binding::Post,
            Binding::SimpleSign,
            Binding::Artifact,
            Binding::Soap,
        ] {
            assert_eq!(Binding::from_short_name(b.short_name()), Some(b));
            assert_eq!(Binding::from_urn(b.urn()), Some(b));
        }
        assert_eq!(Binding::from_short_name("nope"), None);
        assert_eq!(Binding::from_urn("nope"), None);
    }

    #[test]
    fn parser_type_query_param() {
        assert_eq!(ParserType::SamlRequest.query_param(), "SAMLRequest");
        assert_eq!(ParserType::LogoutRequest.query_param(), "SAMLRequest");
        assert_eq!(ParserType::SamlResponse.query_param(), "SAMLResponse");
        assert_eq!(ParserType::LogoutResponse.query_param(), "SAMLResponse");
    }

    #[test]
    fn digest_mapping_matches_xmlsig_values() {
        assert_eq!(
            digest_for_signature(signature_algorithm::RSA_SHA256),
            Some(digest_algorithm::SHA256)
        );
        assert_eq!(
            digest_for_signature(signature_algorithm::RSA_SHA256_MGF1),
            Some(digest_algorithm::SHA256)
        );
        assert_eq!(
            digest_for_signature(signature_algorithm::RSA_SHA1),
            Some("http://www.w3.org/2000/09/xmldsig#sha1")
        );
        assert_eq!(
            digest_for_signature(signature_algorithm::DSA_SHA1),
            Some(digest_algorithm::SHA1)
        );
        assert_eq!(
            digest_for_signature(signature_algorithm::HMAC_SHA1),
            Some(digest_algorithm::SHA1)
        );
        assert_eq!(digest_for_signature("unknown"), None);
    }

    #[test]
    fn status_success_value() {
        assert_eq!(
            status_code::SUCCESS,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
    }
}
