use crate::browser::{Inbound, Transport};
use crate::config::HmacSecret;
use crate::constants::{Binding, ParserType};
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
    now: SystemTime,
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
            now,
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
    run_logout_flow(
        &FlowOptions {
            defer_logout_request_version: true,
            signature_check: receipt.signature,
            require_audience_restriction: true,
            ..FlowOptions::for_peer(
                receipt.decode_as,
                ParserType::LogoutRequest,
                self_setting,
                from_meta,
                validation.peer_hmac_secret,
                validation.now,
                validation.clock_skew,
            )
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
    run_logout_flow(
        &FlowOptions {
            signature_check: receipt.signature,
            require_audience_restriction: true,
            expected_in_response_to: Some(request_id),
            ..FlowOptions::for_peer(
                receipt.decode_as,
                ParserType::LogoutResponse,
                self_setting,
                from_meta,
                validation.peer_hmac_secret,
                validation.now,
                validation.clock_skew,
            )
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
        None => Ok(flow_with_authentication(options, request)?.into_flow_result()),
    }
}
