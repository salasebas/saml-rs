//! XML-DSig signing and detached message signatures, delegating crypto to the
//! selected `bergshamra` provider.

use super::keys::{load_certificate, load_hmac_secret, load_private_key};
use super::xml_syntax::validate_crypto_xml_prefix;
use crate::binding::{base64_decode, base64_encode, xml_escape};
use crate::config::HmacSecret;
use crate::constants::{digest_for_signature, namespace, transform_algorithm};
use crate::entity::{EntitySetting, SignatureAction, SignatureConfig};
use crate::error::SamlError;
use crate::util::normalize_cert_string;
use crate::xml::dom::{self, Node};
use bergshamra::keys::Key;
use bergshamra::{sign, DsigContext, KeysManager};
use quick_xml::events::Event;
use quick_xml::Reader;

fn crypto_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Crypto(err.to_string())
}

fn require_operation_key<T>(
    key: Result<Option<T>, impl std::fmt::Display>,
    missing: &'static str,
) -> Result<T, SamlError> {
    key.map_err(crypto_err)?
        .ok_or_else(|| SamlError::MissingKey(missing.into()))
}

fn find_assertion(root: &Node) -> Option<&Node> {
    if root.local_name == "Assertion" {
        return Some(root);
    }
    root.children.iter().find(|c| c.local_name == "Assertion")
}

/// Extract the `local-name()` chain from an absolute XPath, e.g.
/// `/*[local-name(.)='Response']/*[local-name(.)='Issuer']` → `["Response","Issuer"]`.
fn parse_local_names(xpath: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = xpath;
    let needle = "local-name(.)='";
    while let Some(i) = rest.find(needle) {
        rest = &rest[i + needle.len()..];
        match rest.find('\'') {
            Some(end) => {
                names.push(rest[..end].to_string());
                rest = &rest[end + 1..];
            }
            None => break,
        }
    }
    names
}

/// Resolve an absolute local-name path from the document root.
fn resolve_path<'a>(root: &'a Node, names: &[String]) -> Option<&'a Node> {
    let (first, rest) = names.split_first()?;
    if &root.local_name != first {
        return None;
    }
    let mut current = root;
    for name in rest {
        current = current.children.iter().find(|c| &c.local_name == name)?;
    }
    Some(current)
}

fn xml_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Xml(err.to_string())
}

/// Insert `signature` into `xml` at `action` relative to `node`.
///
/// `Prepend` and `Append` on an empty-element tag such as `<Extensions/>`
/// rewrite it as a start-tag and end-tag pair around the signature.
fn place_signature(
    xml: &str,
    node: &Node,
    action: SignatureAction,
    signature: &str,
) -> Result<String, SamlError> {
    let pos = match action {
        SignatureAction::After => node.end,
        SignatureAction::Before => node.start,
        SignatureAction::Prepend | SignatureAction::Append => {
            let element = &xml[node.start..node.end];
            let mut reader = Reader::from_str(element);
            match reader.read_event().map_err(xml_err)? {
                Event::Empty(tag) => {
                    let name = tag.name().into_inner();
                    let open = xml[..node.end]
                        .strip_suffix("/>")
                        .ok_or_else(|| xml_err("empty-element tag does not end with '/>'"))?;
                    let rest = &xml[node.end..];
                    return Ok(format!("{open}>{signature}</{name}>{rest}"));
                }
                Event::Start(_) if action == SignatureAction::Prepend => {
                    node.start + usize::try_from(reader.buffer_position()).map_err(xml_err)?
                }
                Event::Start(_) => {
                    node.start
                        + element
                            .rfind("</")
                            .ok_or_else(|| xml_err("element has no end tag"))?
                }
                other => {
                    return Err(xml_err(format!(
                        "signature reference does not start with an element tag: {other:?}"
                    )))
                }
            }
        }
    };
    Ok(format!("{}{signature}{}", &xml[..pos], &xml[pos..]))
}

/// Construct and embed an enveloped XML-DSig signature.
///
/// When `sign_message` the whole root is referenced; otherwise the contained
/// `<Assertion>` is referenced. `config` customizes the element prefix and
/// placement; by default the `<Signature>` is inserted right after the target's
/// `<Issuer>`. bergshamra then fills the digest and signature value. Returns
/// the signed XML.
pub fn construct_saml_signature(
    xml: &str,
    sign_message: bool,
    key: &Key,
    cert: &str,
    sig_alg: &str,
    transforms: &[String],
    config: Option<&SignatureConfig>,
) -> Result<String, SamlError> {
    embed_signature(
        xml,
        sign_message,
        key,
        Some(cert),
        sig_alg,
        transforms,
        config,
    )
}

fn embed_signature(
    xml: &str,
    sign_message: bool,
    key: &Key,
    cert: Option<&str>,
    sig_alg: &str,
    transforms: &[String],
    config: Option<&SignatureConfig>,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    let doc = dom::parse(xml)?;
    let target = if sign_message {
        &doc.root
    } else {
        find_assertion(&doc.root)
            .ok_or_else(|| SamlError::MissingMetadata("Assertion to sign".into()))?
    };
    let id = target
        .attr("ID")
        .or_else(|| target.attr("AssertionID"))
        .ok_or_else(|| SamlError::Invalid("signing target has no ID".into()))?;
    let digest = digest_for_signature(sig_alg)
        .ok_or_else(|| SamlError::Crypto(format!("unknown signature algorithm: {sig_alg}")))?;

    let prefix = config.map(|c| c.prefix.as_str()).unwrap_or("ds");
    validate_crypto_xml_prefix("SignatureConfig.prefix", prefix)?;
    let key_info = cert
        .map(|cert| {
            let cert_b64 = xml_escape(&normalize_cert_string(cert));
            format!("<{prefix}:KeyInfo><{prefix}:X509Data><{prefix}:X509Certificate>{cert_b64}</{prefix}:X509Certificate></{prefix}:X509Data></{prefix}:KeyInfo>")
        })
        .unwrap_or_default();
    let id = xml_escape(id);
    let sig_alg = xml_escape(sig_alg);
    let default_transforms = [
        transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
        transform_algorithm::EXC_C14N.to_string(),
    ];
    let effective = if transforms.is_empty() {
        &default_transforms[..]
    } else {
        transforms
    };
    let transforms_xml: String = effective
        .iter()
        .map(|t| {
            let transform = xml_escape(t);
            format!("<{prefix}:Transform Algorithm=\"{transform}\"/>")
        })
        .collect();
    let signature = format!(
        "<{p}:Signature xmlns:{p}=\"{dsig}\"><{p}:SignedInfo><{p}:CanonicalizationMethod Algorithm=\"{exc}\"/><{p}:SignatureMethod Algorithm=\"{sig_alg}\"/><{p}:Reference URI=\"#{id}\"><{p}:Transforms>{transforms_xml}</{p}:Transforms><{p}:DigestMethod Algorithm=\"{digest}\"/><{p}:DigestValue></{p}:DigestValue></{p}:Reference></{p}:SignedInfo><{p}:SignatureValue></{p}:SignatureValue>{key_info}</{p}:Signature>",
        p = prefix,
        dsig = namespace::DSIG,
        exc = transform_algorithm::EXC_C14N,
    );

    let (node, action) = match config.and_then(|c| c.reference.as_deref()) {
        Some(reference) => {
            let names = parse_local_names(reference);
            let node = resolve_path(&doc.root, &names)
                .ok_or_else(|| SamlError::Invalid("signatureConfig reference not found".into()))?;
            (node, config.map(|c| c.action).unwrap_or_default())
        }
        None => {
            let issuer = target
                .children
                .iter()
                .find(|c| c.local_name == "Issuer")
                .ok_or_else(|| SamlError::Invalid("signing target has no Issuer".into()))?;
            (issuer, SignatureAction::After)
        }
    };
    let templated = place_signature(xml, node, action, &signature)?;

    let mut manager = KeysManager::new();
    manager.add_key(key.clone());
    let ctx = DsigContext::new(manager).with_insecure(true);
    sign(&ctx, &templated).map_err(crypto_err)
}

pub(crate) enum SigningCredential<'a> {
    PrivateKey {
        key: Key,
        certificate: Option<&'a str>,
    },
    HmacSecret(Key),
}

impl<'a> SigningCredential<'a> {
    pub(crate) fn from_setting(setting: &'a EntitySetting) -> Result<Self, SamlError> {
        if bergshamra::crypto::sign::is_hmac_algorithm(&setting.request_signature_algorithm) {
            let secret = setting
                .hmac_secret
                .as_ref()
                .ok_or_else(|| SamlError::MissingKey("hmac_secret".into()))?;
            return Ok(Self::HmacSecret(load_hmac_secret(secret)?));
        }
        let pem = setting
            .private_key
            .as_deref()
            .ok_or_else(|| SamlError::MissingKey("private_key".into()))?;
        Ok(Self::PrivateKey {
            key: load_private_key(pem, setting.private_key_pass.as_deref())?,
            certificate: setting.signing_cert.as_deref(),
        })
    }

    pub(crate) fn require_certificate(&self) -> Result<(), SamlError> {
        match self {
            Self::PrivateKey {
                certificate: None, ..
            } => Err(SamlError::MissingKey("signing_cert".into())),
            Self::PrivateKey {
                certificate: Some(_),
                ..
            }
            | Self::HmacSecret(_) => Ok(()),
        }
    }

    pub(crate) fn sign_detached(
        &self,
        octet_string: &str,
        sig_alg: &str,
    ) -> Result<String, SamlError> {
        let key = match self {
            Self::PrivateKey { key, .. } | Self::HmacSecret(key) => key,
        };
        construct_message_signature(octet_string, key, sig_alg)
    }

    pub(crate) fn sign_xml(
        &self,
        xml: &str,
        sign_message: bool,
        sig_alg: &str,
        transforms: &[String],
        config: Option<&SignatureConfig>,
    ) -> Result<String, SamlError> {
        match self {
            Self::PrivateKey { key, certificate } => {
                let certificate =
                    certificate.ok_or_else(|| SamlError::MissingKey("signing_cert".into()))?;
                embed_signature(
                    xml,
                    sign_message,
                    key,
                    Some(certificate),
                    sig_alg,
                    transforms,
                    config,
                )
            }
            Self::HmacSecret(key) => {
                embed_signature(xml, sign_message, key, None, sig_alg, transforms, config)
            }
        }
    }
}

/// Sign a detached octet string (redirect/SimpleSign binding).
///
/// Returns the base64-encoded signature.
pub fn construct_message_signature(
    octet_string: &str,
    key: &Key,
    sig_alg: &str,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    let signing = require_operation_key(key.to_signing_key(), "no signing key")?;
    let alg = bergshamra::crypto::sign::from_uri(sig_alg).map_err(crypto_err)?;
    let signature = alg
        .sign(&signing, octet_string.as_bytes())
        .map_err(crypto_err)?;
    Ok(base64_encode(&signature))
}

/// Verify a detached octet-string signature against `cert`.
pub fn verify_message_signature(
    octet_string: &str,
    signature_b64: &str,
    cert: &str,
    sig_alg: &str,
) -> Result<bool, SamlError> {
    verify_detached_with_key(
        octet_string,
        signature_b64,
        &load_certificate(cert)?,
        sig_alg,
    )
}

pub(crate) fn verify_hmac_message_signature(
    octet_string: &str,
    signature_b64: &str,
    secret: &HmacSecret,
    sig_alg: &str,
) -> Result<bool, SamlError> {
    verify_detached_with_key(
        octet_string,
        signature_b64,
        &load_hmac_secret(secret)?,
        sig_alg,
    )
}

fn verify_detached_with_key(
    octet_string: &str,
    signature_b64: &str,
    key: &Key,
    sig_alg: &str,
) -> Result<bool, SamlError> {
    let verifying = require_operation_key(key.to_signing_key(), "no verification key")?;
    let alg = bergshamra::crypto::sign::from_uri(sig_alg).map_err(crypto_err)?;
    let signature = base64_decode(signature_b64)?;
    alg.verify(&verifying, octet_string.as_bytes(), &signature)
        .map_err(crypto_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "crypto-rustcrypto")]
    use crate::constants::signature_algorithm::RSA_SHA1;
    use crate::constants::signature_algorithm::{RSA_SHA256, RSA_SHA256_MGF1, RSA_SHA512};
    use crate::crypto::keys::load_private_key;
    use crate::crypto::verify::verify_signature;
    use crate::entity::EntitySetting;

    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");

    const AUTHN_REQUEST: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>";

    #[test]
    fn operation_key_maps_provider_failure_to_crypto() {
        let result = require_operation_key::<()>(Err("provider import failed"), "missing");

        assert!(matches!(
            result,
            Err(SamlError::Crypto(message)) if message == "provider import failed"
        ));
    }

    #[test]
    fn operation_key_preserves_missing_key_error() {
        let result = require_operation_key::<()>(Ok::<Option<()>, &str>(None), "no signing key");

        assert!(matches!(
            result,
            Err(SamlError::MissingKey(message)) if message == "no signing key"
        ));
    }

    #[test]
    fn sign_message_then_verify_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        #[cfg(feature = "crypto-rustcrypto")]
        let algorithms = [RSA_SHA1, RSA_SHA256, RSA_SHA512];
        #[cfg(not(feature = "crypto-rustcrypto"))]
        let algorithms = [RSA_SHA256, RSA_SHA512];
        for alg in algorithms {
            let signed =
                construct_saml_signature(AUTHN_REQUEST, true, &key, SP_CERT, alg, &[], None)?;
            assert!(signed.contains("<ds:Signature"));
            assert!(!signed.contains("<ds:SignatureValue></ds:SignatureValue>"));
            let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
            assert!(verified, "self-signed AuthnRequest should verify ({alg})");
        }
        Ok(())
    }

    #[test]
    fn sign_message_with_rsa_pss_sha256_then_verify() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed = construct_saml_signature(
            AUTHN_REQUEST,
            true,
            &key,
            SP_CERT,
            RSA_SHA256_MGF1,
            &[],
            None,
        )?;
        assert!(signed.contains("<ds:Signature"));
        assert!(signed.contains(RSA_SHA256_MGF1));
        assert!(!signed.contains("<ds:SignatureValue></ds:SignatureValue>"));
        let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
        assert!(verified, "self-signed PSS AuthnRequest should verify");
        Ok(())
    }

    #[test]
    fn sign_assertion_then_verify_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed =
            construct_saml_signature(RESPONSE, false, &key, SP_CERT, RSA_SHA256, &[], None)?;
        let (verified, content) = verify_signature(&signed, &[SP_CERT.to_string()])?;
        assert!(verified, "signed assertion should verify");
        assert!(content.ok_or("expected assertion")?.contains("Assertion"));
        Ok(())
    }

    #[test]
    fn custom_signature_config_prefix_and_location() -> Result<(), Box<dyn std::error::Error>> {
        use crate::entity::{SignatureAction, SignatureConfig};
        let key = load_private_key(SP_PRIVKEY, None)?;
        let config = SignatureConfig {
            prefix: "ds2".into(),
            reference: Some("/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']".into()),
            action: SignatureAction::Before,
        };
        let signed = construct_saml_signature(
            AUTHN_REQUEST,
            true,
            &key,
            SP_CERT,
            RSA_SHA256,
            &[],
            Some(&config),
        )?;
        assert!(signed.contains("<ds2:Signature"));
        let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
        assert!(verified, "custom-prefix signature should verify");
        Ok(())
    }

    #[test]
    fn child_placement_inside_reference_element() -> Result<(), Box<dyn std::error::Error>> {
        use crate::entity::{SignatureAction, SignatureConfig};
        let key = load_private_key(SP_PRIVKEY, None)?;
        let empty = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" ProviderName=\"SP > portal\" />";
        let with_issuer = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" ProviderName=\"SP > portal\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>";
        let cases: [(&str, SignatureAction, &[&str]); 4] = [
            (empty, SignatureAction::Prepend, &["Signature"]),
            (empty, SignatureAction::Append, &["Signature"]),
            (
                with_issuer,
                SignatureAction::Prepend,
                &["Signature", "Issuer"],
            ),
            (
                with_issuer,
                SignatureAction::Append,
                &["Issuer", "Signature"],
            ),
        ];
        for (request, action, expected_children) in cases {
            let config = SignatureConfig {
                reference: Some("/*[local-name(.)='AuthnRequest']".into()),
                action,
                ..SignatureConfig::default()
            };
            let signed = construct_saml_signature(
                request,
                true,
                &key,
                SP_CERT,
                RSA_SHA256,
                &[],
                Some(&config),
            )?;
            let root = dom::parse(&signed)?.root;
            let children: Vec<&str> = root
                .children
                .iter()
                .map(|c| c.local_name.as_str())
                .collect();
            assert_eq!(children, expected_children, "{request} {action:?}");
            assert_eq!(root.attr("ProviderName"), Some("SP > portal"));
            let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
            assert!(verified, "{request} {action:?} signature should verify");
        }

        let self_closing_child = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer><samlp:Extensions/><samlp:NameIDPolicy/></samlp:AuthnRequest>";
        for action in [SignatureAction::Prepend, SignatureAction::Append] {
            let config = SignatureConfig {
                reference: Some(
                    "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Extensions']".into(),
                ),
                action,
                ..SignatureConfig::default()
            };
            let signed = construct_saml_signature(
                self_closing_child,
                true,
                &key,
                SP_CERT,
                RSA_SHA256,
                &[],
                Some(&config),
            )?;
            let root = dom::parse(&signed)?.root;
            let children: Vec<&str> = root
                .children
                .iter()
                .map(|c| c.local_name.as_str())
                .collect();
            assert_eq!(
                children,
                ["Issuer", "Extensions", "NameIDPolicy"],
                "{action:?}"
            );
            let extensions: Vec<&str> = root.children[1]
                .children
                .iter()
                .map(|c| c.local_name.as_str())
                .collect();
            assert_eq!(extensions, ["Signature"], "{action:?}");
        }
        Ok(())
    }

    #[test]
    fn explicit_transformation_algorithms_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        use crate::constants::transform_algorithm::{ENVELOPED_SIGNATURE, EXC_C14N};
        let key = load_private_key(SP_PRIVKEY, None)?;
        let transforms = [ENVELOPED_SIGNATURE.to_string(), EXC_C14N.to_string()];
        let signed = construct_saml_signature(
            AUTHN_REQUEST,
            true,
            &key,
            SP_CERT,
            RSA_SHA256,
            &transforms,
            None,
        )?;
        let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
        assert!(verified, "explicit transforms should verify");
        Ok(())
    }

    #[test]
    fn detached_message_signature_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let octet = "SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fexample";
        let sig = construct_message_signature(octet, &key, RSA_SHA256)?;
        assert!(verify_message_signature(octet, &sig, SP_CERT, RSA_SHA256)?);
        assert!(matches!(
            verify_message_signature(octet, &format!("{sig}\u{a0}"), SP_CERT, RSA_SHA256),
            Err(SamlError::Base64(_))
        ));
        // tampered octet string must fail
        assert!(!verify_message_signature(
            "SAMLRequest=TAMPERED",
            &sig,
            SP_CERT,
            RSA_SHA256
        )?);
        Ok(())
    }

    #[test]
    fn detached_message_signature_with_rsa_pss_sha256_round_trip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let octet = "SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fwww.w3.org%2F2007%2F05%2Fxmldsig-more%23sha256-rsa-MGF1";
        let sig = construct_message_signature(octet, &key, RSA_SHA256_MGF1)?;
        assert!(verify_message_signature(
            octet,
            &sig,
            SP_CERT,
            RSA_SHA256_MGF1
        )?);
        Ok(())
    }

    #[test]
    fn default_rsa_sha256_detached_signature_does_not_verify_as_rsa_pss(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let octet =
            "SAMLRequest=abc&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
        let sig = construct_message_signature(octet, &key, RSA_SHA256)?;
        assert!(
            !verify_message_signature(octet, &sig, SP_CERT, RSA_SHA256_MGF1)?,
            "RSA-SHA256 signature must not verify under PSS"
        );
        Ok(())
    }

    #[test]
    fn unknown_signature_algorithm_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let alg = "http://example.com/signature#unknown";
        assert!(construct_message_signature("SAMLRequest=abc", &key, alg).is_err());
        assert!(verify_message_signature("SAMLRequest=abc", "c2lnbmF0dXJl", SP_CERT, alg).is_err());
        assert!(
            construct_saml_signature(AUTHN_REQUEST, true, &key, SP_CERT, alg, &[], None).is_err()
        );
        Ok(())
    }

    #[test]
    fn default_request_signature_algorithm_remains_rsa_sha256() {
        assert_eq!(
            EntitySetting::default().request_signature_algorithm,
            RSA_SHA256
        );
        assert_ne!(
            EntitySetting::default().request_signature_algorithm,
            RSA_SHA256_MGF1
        );
    }
}
