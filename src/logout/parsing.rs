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

use super::encrypted_id::LogoutRequestAuthentication;

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
    signature: LogoutReceiptSignature,
    signed_destination: SignedMessageDestination,
}

#[derive(Debug, Clone, Copy)]
enum LogoutReceiptSignature {
    FollowLocalPolicy,
    Required,
    /// The deployment authenticated the peer. A present signature is verified.
    VerifyIfPresent,
}

impl LogoutReceipt {
    pub(crate) fn of_binding(binding: Binding) -> Self {
        Self {
            decode_as: binding,
            signature: LogoutReceiptSignature::FollowLocalPolicy,
            signed_destination: SignedMessageDestination::Required,
        }
    }

    /// The SOAP body XML arrives as an HTTP-POST message. It must carry an
    /// XML signature unless `channel` authenticated the peer.
    pub(crate) fn of_input<Message>(input: &Inbound<Message>) -> Result<Self, SamlError> {
        match &input.transport {
            Transport::Redirect { .. } => Ok(Self::of_binding(Binding::Redirect)),
            Transport::Post { .. } => Ok(Self::of_binding(Binding::Post)),
            Transport::SimpleSign { .. } => Ok(Self::of_binding(Binding::SimpleSign)),
            Transport::Soap { channel, .. } => Ok(Self {
                decode_as: Binding::Post,
                signature: if channel.authenticates_peer() {
                    LogoutReceiptSignature::VerifyIfPresent
                } else {
                    LogoutReceiptSignature::Required
                },
                signed_destination: SignedMessageDestination::Optional,
            }),
            Transport::Artifact { .. } => Err(SamlError::UnsupportedBinding {
                binding: Binding::Artifact,
            }),
        }
    }

    fn signature_check(self, local_policy_requires_signature: bool) -> SignatureCheck {
        match self.signature {
            LogoutReceiptSignature::FollowLocalPolicy => {
                if local_policy_requires_signature {
                    SignatureCheck::Require
                } else {
                    SignatureCheck::Skip
                }
            }
            LogoutReceiptSignature::Required => SignatureCheck::Require,
            LogoutReceiptSignature::VerifyIfPresent => SignatureCheck::VerifyIfPresent,
        }
    }

    /// A verified signature authenticates the message. On a SOAP channel that
    /// authenticated the peer, the channel does.
    fn authentication(self, signature_verified: bool) -> LogoutRequestAuthentication {
        match (self.signature, signature_verified) {
            (
                LogoutReceiptSignature::FollowLocalPolicy
                | LogoutReceiptSignature::Required
                | LogoutReceiptSignature::VerifyIfPresent,
                true,
            )
            | (LogoutReceiptSignature::VerifyIfPresent, false) => {
                LogoutRequestAuthentication::Authenticated
            }
            (
                LogoutReceiptSignature::FollowLocalPolicy | LogoutReceiptSignature::Required,
                false,
            ) => LogoutRequestAuthentication::Unauthenticated,
        }
    }
}

/// Typed `LogoutRequest` parsing. The returned authentication selects
/// whether [`super::decrypt_encrypted_id`] decrypts an `<EncryptedID>`.
pub(crate) fn parse_logout_request_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    validation: LogoutFlowValidation<'_>,
) -> Result<(FlowResult, LogoutRequestAuthentication), SamlError> {
    let (flow, signature_verified) =
        parse_logout_request_inner(self_setting, from_meta, receipt, request, validation)?;
    Ok((flow, receipt.authentication(signature_verified)))
}

/// The flow result and whether a signature authenticated the message.
fn parse_logout_request_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    validation: LogoutFlowValidation<'_>,
) -> Result<(FlowResult, bool), SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    run_logout_flow(
        &FlowOptions {
            binding: Some(receipt.decode_as),
            parser_type: Some(ParserType::LogoutRequest),
            signature_check: receipt.signature_check(self_setting.want_logout_request_signed),
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

fn parse_logout_response_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    receipt: LogoutReceipt,
    request: &HttpRequest,
    expected_in_response_to: Option<&str>,
    validation: LogoutFlowValidation<'_>,
) -> Result<FlowResult, SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    Ok(run_logout_flow(
        &FlowOptions {
            binding: Some(receipt.decode_as),
            parser_type: Some(ParserType::LogoutResponse),
            signature_check: receipt.signature_check(self_setting.want_logout_response_signed),
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
            expected_in_response_to,
        },
        request,
        validation.expected_recipient,
        receipt.signed_destination,
    )?
    .0)
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
    parse_logout_response_inner(
        self_setting,
        from_meta,
        receipt,
        request,
        Some(request_id),
        validation,
    )
}

/// The flow result and whether a signature authenticated the message.
fn run_logout_flow(
    options: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
    signed_destination: SignedMessageDestination,
) -> Result<(FlowResult, bool), SamlError> {
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
            let message_authenticated = result.message_authenticated();
            Ok((result.into_parts().0, message_authenticated))
        }
        None => flow_with_authentication(options, request),
    }
}
