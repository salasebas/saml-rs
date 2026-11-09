#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::binding::base64_encode;
use crate::constants::{Binding, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
pub(super) fn sign_logout(
    setting: &EntitySetting,
    binding: Binding,
    xml: &str,
    destination: &str,
    relay: Option<&str>,
    parser_type: ParserType,
) -> Result<(String, Option<String>, Option<String>), SamlError> {
    use crate::binding::{append_signature, build_redirect_octet};
    use crate::crypto::{
        construct_message_signature, construct_saml_signature, keys::load_private_key,
    };

    if matches!(binding, Binding::Artifact) {
        return Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        });
    }

    let sig_alg = &setting.request_signature_algorithm;
    let key_pem = setting
        .private_key
        .as_deref()
        .ok_or_else(|| SamlError::MissingKey("private_key".into()))?;
    let key = load_private_key(key_pem, setting.private_key_pass.as_deref())?;
    let embedded_signature = || {
        let cert = setting
            .signing_cert
            .as_deref()
            .ok_or_else(|| SamlError::MissingKey("signing_cert".into()))?;
        construct_saml_signature(
            xml,
            true,
            &key,
            cert,
            sig_alg,
            &setting.transformation_algorithms,
            setting.signature_config.as_ref(),
        )
    };
    match binding {
        Binding::Redirect => {
            let octet = build_redirect_octet(parser_type, xml, relay, sig_alg)?;
            let sig = construct_message_signature(&octet, &key, sig_alg)?;
            Ok((append_signature(destination, &octet, &sig), None, None))
        }
        Binding::Post => Ok((base64_encode(embedded_signature()?.as_bytes()), None, None)),
        Binding::Soap => Ok((embedded_signature()?, None, None)),
        Binding::SimpleSign => {
            let octet = crate::binding::build_simplesign_octet(
                parser_type.query_param(),
                xml,
                relay,
                sig_alg,
            );
            let sig = construct_message_signature(&octet, &key, sig_alg)?;
            Ok((
                base64_encode(xml.as_bytes()),
                Some(sig),
                Some(sig_alg.clone()),
            ))
        }
        Binding::Artifact => Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        }),
    }
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
pub(super) fn sign_logout(
    _setting: &EntitySetting,
    _binding: Binding,
    _xml: &str,
    _destination: &str,
    _relay: Option<&str>,
    _parser_type: ParserType,
) -> Result<(String, Option<String>, Option<String>), SamlError> {
    Err(SamlError::Unsupported(
        "signing logout messages requires a crypto provider feature".into(),
    ))
}
