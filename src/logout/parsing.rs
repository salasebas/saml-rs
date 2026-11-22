use crate::browser::{Inbound, Transport};
use crate::config::HmacSecret;
use crate::config::{AssertionElementEncryption, ReceivedEncryptedElements};
use crate::constants::{Binding, CertUse, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::{
    flow_with_authentication, flow_with_expected_recipient_and_signature_evidence,
    AssertionSignatureRequirement, FlowOptions, FlowResult, HttpRequest,
    ResponseSignatureRequirement, SignatureCheck, SignedMessageDestination,
};
use crate::metadata::Metadata;
use crate::model::ClockSkew;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy)]
pub(crate) struct LogoutFlowValidation<'a> {
    expected_recipient: Option<&'a str>,
    now: Option<SystemTime>,
    clock_skew: ClockSkew,
    peer_hmac_secret: Option<&'a HmacSecret>,
}

impl<'a> LogoutFlowValidation<'a> {
    /// `expected_recipient` is the local endpoint a present `Destination`
    /// must name. `None` is a SOAP response, which has no receiving endpoint.
    pub(crate) fn typed(
        expected_recipient: Option<&'a str>,
        now: SystemTime,
        clock_skew: ClockSkew,
        peer_hmac_secret: Option<&'a HmacSecret>,
    ) -> Self {
        Self {
            expected_recipient,
            now: Some(now),
            clock_skew,
            peer_hmac_secret,
        }
    }
}

/// How the flow reads a logout message from one typed input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LogoutReceipt {
    decode_as: Binding,
    signature: SignatureCheck,
    signed_destination: SignedMessageDestination,
}

impl LogoutReceipt {
    pub(crate) fn browser(binding: Binding) -> Self {
        Self {
            decode_as: binding,
            signature: SignatureCheck::Require,
            signed_destination: SignedMessageDestination::Required,
        }
    }

    /// The SOAP body XML arrives as an HTTP-POST message. It must carry an
    /// XML signature unless `channel` authenticated the peer.
    pub(crate) fn of_input<Message>(input: &Inbound<Message>) -> Result<Self, SamlError> {
        match &input.transport {
            Transport::Redirect { .. } => Ok(Self::browser(Binding::Redirect)),
            Transport::Post { .. } => Ok(Self::browser(Binding::Post)),
            Transport::SimpleSign { .. } => Ok(Self::browser(Binding::SimpleSign)),
            Transport::Soap { channel, .. } => Ok(Self::soap(*channel)),
            Transport::Artifact { .. } => Err(SamlError::UnsupportedBinding {
                binding: Binding::Artifact,
            }),
        }
    }

    pub(crate) fn soap(channel: crate::SoapChannel) -> Self {
        Self {
            decode_as: Binding::Post,
            signature: if channel.authenticates_peer() {
                SignatureCheck::VerifyIfPresent
            } else {
                SignatureCheck::Require
            },
            signed_destination: SignedMessageDestination::Optional,
        }
    }
}

pub(crate) fn parse_logout_request_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    run_logout_flow(
        &FlowOptions {
            binding: Some(receipt.decode_as),
            parser_type: Some(ParserType::LogoutRequest),
            signature_check: receipt.signature,
            require_audience_restriction: true,
            xml_signatures: self_setting.xml_signatures,
            from_issuer: from_meta.entity_id(),
            signing_certs,
            hmac_secret: validation.peer_hmac_secret,
            decrypt_key: None,
            decrypt_key_pass: None,
            additional_decrypt_keys: &[],
            assertion_elements: AssertionElementEncryption::default(),
            element_decrypt_key: None,
            received_encrypted_elements: ReceivedEncryptedElements::DecryptSelected,
            allow_rsa15_key_transport_decryption: false,
            max_decryption_work: self_setting.max_decryption_work,
            clock_skew: validation.clock_skew,
            now: validation.now,
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            schema_validator: self_setting.schema_validator,
            expected_audience: None,
            expected_in_response_to: None,
        },
        request,
        validation.expected_recipient,
        receipt.signed_destination,
    )
}

pub(crate) fn parse_logout_response_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    request_id: &str,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    run_logout_flow(
        &FlowOptions {
            binding: Some(receipt.decode_as),
            parser_type: Some(ParserType::LogoutResponse),
            signature_check: receipt.signature,
            require_audience_restriction: true,
            xml_signatures: self_setting.xml_signatures,
            from_issuer: from_meta.entity_id(),
            signing_certs,
            hmac_secret: validation.peer_hmac_secret,
            decrypt_key: None,
            decrypt_key_pass: None,
            additional_decrypt_keys: &[],
            assertion_elements: AssertionElementEncryption::default(),
            element_decrypt_key: None,
            received_encrypted_elements: ReceivedEncryptedElements::DecryptSelected,
            allow_rsa15_key_transport_decryption: false,
            max_decryption_work: self_setting.max_decryption_work,
            clock_skew: validation.clock_skew,
            now: validation.now,
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            schema_validator: self_setting.schema_validator,
            expected_audience: None,
            expected_in_response_to: Some(request_id),
        },
        request,
        validation.expected_recipient,
        receipt.signed_destination,
    )
}

fn run_logout_flow(
    options: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
    signed_destination: SignedMessageDestination,
) -> Result<FlowResult, SamlError> {
    match expected_recipient {
        Some(expected_recipient) => {
            let result = flow_with_expected_recipient_and_signature_evidence(
                options,
                request,
                expected_recipient,
                AssertionSignatureRequirement::Compatible,
                ResponseSignatureRequirement::Optional,
                signed_destination,
            )?;
            Ok(result.into_parts().0)
        }
        None => Ok(flow_with_authentication(options, request)?.0),
    }
}
