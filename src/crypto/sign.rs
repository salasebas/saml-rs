use super::keys::{load_certificate, load_hmac_secret, read_private_key};
use super::signature_profile::check_verification_key;
use crate::binding::{encode_base64, xml_escape};
use crate::config::{HmacSecret, XmlSignatureProfile};
use crate::constants::{digest_algorithm, namespace, signature_algorithm, transform_algorithm};
use crate::entity::EntitySetting;
use crate::error::{crypto_err, xml_err, SamlError};
use crate::util::normalize_cert_string;
use crate::xml::dom::{self, Node};
use crate::xml::name::validate_namespace_prefix;
use bergshamra::keys::Key;
use bergshamra::{sign, DsigContext, KeysManager};
use quick_xml::events::Event;
use quick_xml::Reader;

fn reference_digest_for_signature(sig_alg: &str) -> &'static str {
    match sig_alg {
        signature_algorithm::RSA_SHA1
        | signature_algorithm::DSA_SHA1
        | signature_algorithm::HMAC_SHA1 => digest_algorithm::SHA1,
        signature_algorithm::RSA_SHA384 => digest_algorithm::SHA384,
        signature_algorithm::RSA_SHA512 => digest_algorithm::SHA512,
        _ => digest_algorithm::SHA256,
    }
}

fn require_operation_key<T>(
    key: Result<Option<T>, impl std::error::Error + Send + Sync + 'static>,
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

enum SignatureSlot {
    At(usize),
    ExpandEmpty { name: String, end: usize },
}

fn signature_slot(xml: &str, target: &Node) -> Result<SignatureSlot, SamlError> {
    if let Some(issuer) = target
        .children
        .first()
        .filter(|child| child.local_name == "Issuer")
    {
        return Ok(SignatureSlot::At(issuer.end));
    }
    let element = &xml[target.start..target.end];
    let mut reader = Reader::from_str(element);
    match reader.read_event().map_err(xml_err)? {
        Event::Empty(tag) => Ok(SignatureSlot::ExpandEmpty {
            name: tag.name().into_inner().to_owned(),
            end: target.end,
        }),
        Event::Start(_) => Ok(SignatureSlot::At(
            target.start + usize::try_from(reader.buffer_position()).map_err(xml_err)?,
        )),
        other => Err(SamlError::xml(format!(
            "signing target does not start with an element tag: {other:?}"
        ))),
    }
}

fn insert_signature(xml: &str, slot: SignatureSlot, signature: &str) -> Result<String, SamlError> {
    match slot {
        SignatureSlot::At(position) => Ok(format!(
            "{}{signature}{}",
            &xml[..position],
            &xml[position..]
        )),
        SignatureSlot::ExpandEmpty { name, end } => {
            let open = xml[..end]
                .strip_suffix("/>")
                .ok_or_else(|| SamlError::xml("empty-element tag does not end with '/>'"))?;
            Ok(format!("{open}>{signature}</{name}>{}", &xml[end..]))
        }
    }
}

#[cfg(test)]
pub(crate) fn sign_saml_xml(
    xml: &str,
    sign_message: bool,
    key: &Key,
    cert: &str,
    sig_alg: &str,
    transforms: &[String],
    prefix: Option<&str>,
) -> Result<String, SamlError> {
    embed_signature(
        xml,
        sign_message,
        key,
        Some(cert),
        sig_alg,
        transforms,
        prefix.unwrap_or("ds"),
    )
}

fn embed_signature(
    xml: &str,
    sign_message: bool,
    key: &Key,
    cert: Option<&str>,
    sig_alg: &str,
    transforms: &[String],
    prefix: &str,
) -> Result<String, SamlError> {
    super::provider::ensure_crypto_provider_initialized()?;
    let doc = dom::parse_document(xml, crate::XmlLimits::default())?;
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
    let digest = reference_digest_for_signature(sig_alg);

    validate_namespace_prefix("signature prefix", prefix)?;
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

    let templated = insert_signature(xml, signature_slot(xml, target)?, &signature)?;

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
            key: read_private_key(pem, setting.private_key_pass.as_deref())?,
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
        sign_octet_string(octet_string, key, sig_alg)
    }

    pub(crate) fn sign_xml(
        &self,
        xml: &str,
        sign_message: bool,
        sig_alg: &str,
        transforms: &[String],
        prefix: &str,
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
                    prefix,
                )
            }
            Self::HmacSecret(key) => {
                embed_signature(xml, sign_message, key, None, sig_alg, transforms, prefix)
            }
        }
    }
}

pub(crate) fn sign_octet_string(
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
    Ok(encode_base64(&signature))
}

#[cfg(test)]
pub(crate) fn verify_octet_string_signature(
    octet_string: &str,
    signature_b64: &str,
    cert: &str,
    sig_alg: &str,
) -> Result<bool, SamlError> {
    verify_message_signature_under_profile(
        octet_string,
        &crate::binding::decode_base64(signature_b64)?,
        cert,
        sig_alg,
        XmlSignatureProfile::AllowWeakAlgorithms,
    )
}

pub(crate) fn verify_message_signature_under_profile(
    octet_string: &str,
    signature: &[u8],
    cert: &str,
    sig_alg: &str,
    profile: XmlSignatureProfile,
) -> Result<bool, SamlError> {
    let key = load_certificate(cert)?;
    check_verification_key(profile, &key)?;
    verify_detached_with_key(octet_string, signature, &key, sig_alg)
}

pub(crate) fn verify_hmac_message_signature(
    octet_string: &str,
    signature: &[u8],
    secret: &HmacSecret,
    sig_alg: &str,
) -> Result<bool, SamlError> {
    verify_detached_with_key(octet_string, signature, &load_hmac_secret(secret)?, sig_alg)
}

fn verify_detached_with_key(
    octet_string: &str,
    signature: &[u8],
    key: &Key,
    sig_alg: &str,
) -> Result<bool, SamlError> {
    let verifying = require_operation_key(key.to_signing_key(), "no verification key")?;
    let alg = bergshamra::crypto::sign::from_uri(sig_alg).map_err(crypto_err)?;
    alg.verify(&verifying, octet_string.as_bytes(), signature)
        .map_err(crypto_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "crypto-rustcrypto")]
    use crate::constants::signature_algorithm::RSA_SHA1;
    use crate::constants::signature_algorithm::{RSA_SHA256, RSA_SHA256_MGF1, RSA_SHA512};
    use crate::crypto::keys::read_private_key;
    use crate::crypto::verify::verify_signature;
    use crate::entity::EntitySetting;

    const SP_PRIVKEY: &str =
        include_str!("../../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    const RESPONSE: &str = include_str!("../../tests/fixtures/misc/response.xml");

    const AUTHN_REQUEST: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>";

    #[test]
    fn digest_mapping_matches_xmlsig_values() {
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::RSA_SHA1),
            "http://www.w3.org/2000/09/xmldsig#sha1"
        );
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::DSA_SHA1),
            digest_algorithm::SHA1
        );
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::HMAC_SHA1),
            digest_algorithm::SHA1
        );
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::RSA_SHA256),
            digest_algorithm::SHA256
        );
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::RSA_SHA256_MGF1),
            digest_algorithm::SHA256
        );
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::RSA_SHA384),
            digest_algorithm::SHA384
        );
        assert_eq!(
            reference_digest_for_signature(signature_algorithm::RSA_SHA512),
            digest_algorithm::SHA512
        );
        for alg in [
            signature_algorithm::ECDSA_SHA256,
            signature_algorithm::ECDSA_SHA384,
            signature_algorithm::ECDSA_SHA512,
            signature_algorithm::EDDSA_ED25519,
            "unknown",
        ] {
            assert_eq!(
                reference_digest_for_signature(alg),
                digest_algorithm::SHA256,
                "{alg}"
            );
        }
    }

    #[test]
    fn operation_key_maps_provider_failure_to_crypto() {
        let result = require_operation_key::<()>(
            Err(std::io::Error::other("provider import failed")),
            "missing",
        );

        assert!(matches!(
            result,
            Err(SamlError::Crypto { source: Some(source), .. })
                if source.to_string() == "provider import failed"
        ));
    }

    #[test]
    fn operation_key_preserves_missing_key_error() {
        let result =
            require_operation_key::<()>(Ok::<Option<()>, std::io::Error>(None), "no signing key");

        assert!(matches!(
            result,
            Err(SamlError::MissingKey(message)) if message == "no signing key"
        ));
    }

    #[test]
    fn sign_message_then_verify_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        #[cfg(feature = "crypto-rustcrypto")]
        let algorithms = [RSA_SHA1, RSA_SHA256, RSA_SHA512];
        #[cfg(not(feature = "crypto-rustcrypto"))]
        let algorithms = [RSA_SHA256, RSA_SHA512];
        for alg in algorithms {
            let signed = sign_saml_xml(AUTHN_REQUEST, true, &key, SP_CERT, alg, &[], None)?;
            assert!(signed.contains("<ds:Signature"));
            assert!(!signed.contains("<ds:SignatureValue></ds:SignatureValue>"));
            let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
            assert!(verified, "self-signed AuthnRequest should verify ({alg})");
        }
        Ok(())
    }

    #[test]
    fn sign_message_with_rsa_pss_sha256_then_verify() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        let signed = sign_saml_xml(
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
        let key = read_private_key(SP_PRIVKEY, None)?;
        let signed = sign_saml_xml(RESPONSE, false, &key, SP_CERT, RSA_SHA256, &[], None)?;
        let (verified, content) = verify_signature(&signed, &[SP_CERT.to_string()])?;
        assert!(verified, "signed assertion should verify");
        assert!(content.ok_or("expected assertion")?.contains("Assertion"));
        Ok(())
    }

    #[test]
    fn signature_goes_after_issuer_or_first() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        let with_issuer = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" ProviderName=\"SP > portal\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer><samlp:Extensions/><samlp:NameIDPolicy/></samlp:AuthnRequest>";
        let without_issuer = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" ProviderName=\"SP > portal\"><samlp:Extensions/><samlp:NameIDPolicy/></samlp:AuthnRequest>";
        let empty = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\" ProviderName=\"SP > portal\" />";
        let cases: [(&str, &[&str]); 3] = [
            (
                with_issuer,
                &["Issuer", "Signature", "Extensions", "NameIDPolicy"],
            ),
            (without_issuer, &["Signature", "Extensions", "NameIDPolicy"]),
            (empty, &["Signature"]),
        ];
        for (request, expected_children) in cases {
            let signed = sign_saml_xml(request, true, &key, SP_CERT, RSA_SHA256, &[], None)?;
            let root = dom::parse_document(&signed, crate::XmlLimits::default())?.root;
            let children: Vec<&str> = root
                .children
                .iter()
                .map(|c| c.local_name.as_str())
                .collect();
            assert_eq!(children, expected_children, "{request}");
            assert_eq!(root.attr("ProviderName"), Some("SP > portal"));
            let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
            assert!(verified, "{request} signature should verify");
        }
        Ok(())
    }

    #[test]
    fn explicit_transformation_algorithms_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        use crate::constants::transform_algorithm::{ENVELOPED_SIGNATURE, EXC_C14N};
        let key = read_private_key(SP_PRIVKEY, None)?;
        let transforms = [ENVELOPED_SIGNATURE.to_string(), EXC_C14N.to_string()];
        let signed = sign_saml_xml(
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
        let key = read_private_key(SP_PRIVKEY, None)?;
        let octet = "SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fexample";
        let sig = sign_octet_string(octet, &key, RSA_SHA256)?;
        assert!(verify_octet_string_signature(
            octet, &sig, SP_CERT, RSA_SHA256
        )?);
        assert!(matches!(
            verify_octet_string_signature(octet, &format!("{sig}\u{a0}"), SP_CERT, RSA_SHA256),
            Err(SamlError::Base64 { .. })
        ));
        assert!(!verify_octet_string_signature(
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
        let key = read_private_key(SP_PRIVKEY, None)?;
        let octet = "SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fwww.w3.org%2F2007%2F05%2Fxmldsig-more%23sha256-rsa-MGF1";
        let sig = sign_octet_string(octet, &key, RSA_SHA256_MGF1)?;
        assert!(verify_octet_string_signature(
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
        let key = read_private_key(SP_PRIVKEY, None)?;
        let octet =
            "SAMLRequest=abc&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
        let sig = sign_octet_string(octet, &key, RSA_SHA256)?;
        assert!(
            !verify_octet_string_signature(octet, &sig, SP_CERT, RSA_SHA256_MGF1)?,
            "RSA-SHA256 signature must not verify under PSS"
        );
        Ok(())
    }

    #[test]
    fn unknown_signature_algorithm_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let key = read_private_key(SP_PRIVKEY, None)?;
        let alg = "http://example.com/signature#unknown";
        assert!(sign_octet_string("SAMLRequest=abc", &key, alg).is_err());
        assert!(
            verify_octet_string_signature("SAMLRequest=abc", "c2lnbmF0dXJl", SP_CERT, alg).is_err()
        );
        assert!(sign_saml_xml(AUTHN_REQUEST, true, &key, SP_CERT, alg, &[], None).is_err());
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
