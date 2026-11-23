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
    use crate::constants::transform_algorithm;
    use crate::crypto::SigningCredential;

    if matches!(binding, Binding::Artifact) {
        return Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        });
    }

    let sig_alg = &setting.request_signature_algorithm;
    let credential = SigningCredential::from_setting(setting)?;
    let embedded_signature = |transforms: &[String]| {
        credential.sign_xml(
            xml,
            true,
            sig_alg,
            transforms,
            setting.signature_config.as_ref(),
        )
    };
    let (content, signature, sig_alg) = match binding {
        Binding::Redirect | Binding::SimpleSign => sign_detached_message(
            &credential,
            binding,
            xml,
            destination,
            relay,
            parser_type,
            sig_alg,
        ),
        Binding::Post => Ok((
            encode_base64(embedded_signature(&setting.transformation_algorithms)?.as_bytes()),
            None,
            None,
        )),
        Binding::Soap => Ok((
            embedded_signature(&[
                transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
                transform_algorithm::EXC_C14N.to_string(),
            ])?,
            None,
            None,
        )),
        Binding::Artifact => Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        }),
    }?;
    Ok(SignedMessage {
        content,
        signature,
        sig_alg,
        binding,
        parser_type,
    })
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
