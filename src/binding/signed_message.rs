#[cfg(crypto)]
use crate::binding::encode_base64;
use crate::constants::{Binding, ParserType};
use crate::entity::{BindingContext, EntitySetting};
use crate::error::SamlError;

pub(crate) struct SignedMessage {
    pub(crate) content: String,
    signature: Option<String>,
    sig_alg: Option<String>,
    binding: Binding,
    parser_type: ParserType,
}

impl SignedMessage {
    pub(crate) fn bind(
        self,
        id: String,
        destination: String,
        relay_state: Option<&str>,
    ) -> BindingContext {
        BindingContext {
            id,
            context: self.content,
            signature: self.signature,
            sig_alg: self.sig_alg,
            relay_state: relay_state.map(str::to_owned),
            entity_endpoint: destination,
            binding: self.binding,
            request_type: self.parser_type.query_param(),
        }
    }
}

#[cfg(crypto)]
pub(crate) fn sign_message(
    setting: &EntitySetting,
    binding: Binding,
    xml: &str,
    destination: &str,
    relay: Option<&str>,
    parser_type: ParserType,
) -> Result<SignedMessage, SamlError> {
    use crate::binding::sign_detached_message;
    use crate::crypto::SigningCredential;

    let sig_alg = &setting.request_signature_algorithm;
    let (content, signature, sig_alg) = match binding {
        Binding::Redirect | Binding::SimpleSign => sign_detached_message(
            &SigningCredential::from_setting(setting)?,
            binding,
            xml,
            destination,
            relay,
            parser_type,
            sig_alg,
        )?,
        Binding::Post => {
            let signed = SigningCredential::from_setting(setting)?.sign_xml(
                xml,
                true,
                sig_alg,
                &setting.transformation_algorithms,
                &setting.signature_prefix,
            )?;
            (encode_base64(signed.as_bytes()), None, None)
        }
        Binding::Soap => (sign_soap_message(setting, xml)?, None, None),
        Binding::Artifact => return Err(SamlError::UnsupportedBinding { binding }),
    };
    Ok(SignedMessage {
        content,
        signature,
        sig_alg,
        binding,
        parser_type,
    })
}

#[cfg(crypto)]
pub(crate) fn sign_soap_message(setting: &EntitySetting, xml: &str) -> Result<String, SamlError> {
    use crate::constants::transform_algorithm;
    use crate::crypto::SigningCredential;

    SigningCredential::from_setting(setting)?.sign_xml(
        xml,
        true,
        &setting.request_signature_algorithm,
        &[
            transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
            transform_algorithm::EXC_C14N.to_string(),
        ],
        &setting.signature_prefix,
    )
}

#[cfg(not(crypto))]
pub(crate) fn sign_soap_message(_setting: &EntitySetting, _xml: &str) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "signing SOAP messages requires a crypto provider feature".into(),
    ))
}

#[cfg(not(crypto))]
pub(crate) fn sign_message(
    _setting: &EntitySetting,
    _binding: Binding,
    _xml: &str,
    _destination: &str,
    _relay: Option<&str>,
    _parser_type: ParserType,
) -> Result<SignedMessage, SamlError> {
    Err(SamlError::Unsupported(
        "signing logout messages requires a crypto provider feature".into(),
    ))
}
