use crate::assertion_acceptance::reject_unsolicited_bearer_in_response_to;
use crate::binding::{build_redirect_url, encode_base64};
use crate::constants::{Binding, CertUse, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting};
use crate::error::SamlError;
use crate::flow::{
    validate_received_message, AssertionSignatureRequirement, FlowOptions,
    FlowResultWithSignatureEvidence, HttpRequest, ReceivedMessage, ResponseSignatureRequirement,
    SignatureCheck, SignedMessageDestination,
};
use crate::idp;
use crate::metadata::{generate_sp_metadata, SpMetadata, SpMetadataInput};
use crate::model::{validate_name_id_format, ClockSkew};
use std::time::SystemTime;

mod authn_request;

use crate::xml::write::Prefixes;
pub(crate) use authn_request::AuthnRequestPreferences;
use authn_request::{render_default_authn_request_xml, AuthnRequestXml};

#[derive(Debug, Clone)]
pub struct Engine {
    pub setting: EntitySetting,
    pub metadata: SpMetadata,
}

#[derive(Default)]
pub struct LoginRequestOptions<'a> {
    pub relay_state: Option<&'a str>,
    pub force_authn: Option<bool>,
    pub assertion_consumer_service_index: Option<u16>,
    pub response_binding: Option<Binding>,
}

#[derive(Debug, Clone, Copy)]
enum LoginResponseCorrelation<'a> {
    Unsolicited,
    MessageId(&'a str),
}

#[derive(Clone, Copy)]
pub(crate) struct LoginResponseParseOptions<'a> {
    expected_recipient: Option<&'a str>,
    now: Option<SystemTime>,
    clock_skew: ClockSkew,
    signed_destination: SignedMessageDestination,
}

impl<'a> LoginResponseParseOptions<'a> {
    pub(crate) fn at(now: SystemTime, clock_skew: ClockSkew) -> Self {
        Self {
            expected_recipient: None,
            now: Some(now),
            clock_skew,
            signed_destination: SignedMessageDestination::Required,
        }
    }

    pub(crate) fn signed_destination(
        mut self,
        signed_destination: SignedMessageDestination,
    ) -> Self {
        self.signed_destination = signed_destination;
        self
    }

    pub(crate) fn expected_recipient(mut self, expected_recipient: &'a str) -> Self {
        self.expected_recipient = Some(expected_recipient);
        self
    }
}

impl Engine {
    pub fn from_metadata(xml: &str, setting: EntitySetting) -> Result<Self, SamlError> {
        Ok(Self::from_parsed_metadata(
            SpMetadata::from_xml(xml)?,
            setting,
        ))
    }

    pub(crate) fn from_parsed_metadata(metadata: SpMetadata, mut setting: EntitySetting) -> Self {
        setting.want_assertions_signed = metadata.want_assertions_signed();
        let formats = metadata.as_metadata().name_id_formats();
        if !formats.is_empty() {
            setting.name_id_format = formats
                .iter()
                .map(|format| format.as_uri().to_string())
                .collect();
        }
        if setting.entity_id.is_none() {
            setting.entity_id = metadata.as_metadata().entity_id().map(str::to_string);
        }
        Self { setting, metadata }
    }

    pub fn from_config(
        config: &SpMetadataInput,
        setting: EntitySetting,
    ) -> Result<Self, SamlError> {
        Self::from_metadata(&generate_sp_metadata(config)?, setting)
    }

    pub fn metadata_xml(&self) -> &str {
        self.metadata.as_metadata().metadata_xml()
    }

    fn entity_id(&self) -> String {
        self.setting
            .entity_id
            .clone()
            .or_else(|| self.metadata.as_metadata().entity_id().map(str::to_string))
            .unwrap_or_default()
    }

    pub(crate) fn create_typed_login_request(
        &self,
        idp: &idp::Engine,
        binding: Binding,
        options: &LoginRequestOptions<'_>,
        preferences: &AuthnRequestPreferences<'_>,
    ) -> Result<BindingContext, SamlError> {
        let name_id_format = self.setting.default_name_id_format();
        preferences.validate(name_id_format)?;
        if idp.metadata.want_authn_requests_signed() && !self.metadata.authn_requests_signed() {
            return Err(SamlError::AuthnRequestSigningRequired);
        }
        let destination = idp
            .metadata
            .single_sign_on_location(binding)
            .ok_or_else(|| SamlError::MissingMetadata("SingleSignOnService".into()))?;
        let uses_acs_index = options.assertion_consumer_service_index.is_some();
        let response_binding = options.response_binding.unwrap_or(Binding::Post);
        let acs_url = if uses_acs_index {
            None
        } else {
            Some(
                self.metadata
                    .assertion_consumer_location(response_binding)
                    .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?,
            )
        };
        let protocol_binding = (!uses_acs_index).then(|| response_binding.urn().to_string());
        validate_name_id_format(name_id_format)?;
        let id = generate_id();
        let issue_instant = now_iso8601();
        let issuer = self.entity_id();
        let request = AuthnRequestXml {
            id: &id,
            issue_instant: &issue_instant,
            destination: &destination,
            force_authn: options.force_authn,
            protocol_binding: protocol_binding.as_deref(),
            assertion_consumer_service_url: acs_url.as_deref(),
            assertion_consumer_service_index: options.assertion_consumer_service_index,
            is_passive: preferences.is_passive,
            provider_name: preferences.provider_name,
            requested_authn_context: preferences.requested_authn_context,
            extensions: preferences.extensions,
            issuer: &issuer,
            name_id_format,
            sp_name_qualifier: preferences.sp_name_qualifier,
            allow_create: self.setting.allow_create,
        };
        let xml = render_default_authn_request_xml(Prefixes::of(&self.setting)?, &request);
        let relay_state = options.relay_state.map(str::to_owned);

        if self.metadata.authn_requests_signed() {
            return self.signed_request_context(binding, &xml, destination, relay_state, id);
        }

        let context = match binding {
            Binding::Redirect => build_redirect_url(
                &destination,
                ParserType::SamlRequest,
                &xml,
                relay_state.as_deref(),
            )?,
            Binding::Post | Binding::SimpleSign => encode_base64(xml.as_bytes()),
            Binding::Artifact | Binding::Soap => {
                return Err(SamlError::UnsupportedBinding { binding });
            }
        };
        Ok(BindingContext {
            id,
            context,
            relay_state,
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature: None,
            sig_alg: None,
        })
    }

    #[cfg(crypto)]
    fn signed_request_context(
        &self,
        binding: Binding,
        xml: &str,
        destination: String,
        relay_state: Option<String>,
        id: String,
    ) -> Result<BindingContext, SamlError> {
        use crate::binding::sign_detached_message;
        use crate::crypto::SigningCredential;

        let credential = SigningCredential::from_setting(&self.setting)?;
        credential.require_certificate()?;
        let sig_alg = &self.setting.request_signature_algorithm;

        let (context, signature, sig_alg_out) = match binding {
            Binding::Redirect | Binding::SimpleSign => sign_detached_message(
                &credential,
                binding,
                xml,
                &destination,
                relay_state.as_deref(),
                ParserType::SamlRequest,
                sig_alg,
            )?,
            Binding::Post => {
                let signed = credential.sign_xml(
                    xml,
                    true,
                    sig_alg,
                    &self.setting.transformation_algorithms,
                    self.setting.signature_config.as_ref(),
                )?;
                (encode_base64(signed.as_bytes()), None, None)
            }
            Binding::Artifact | Binding::Soap => {
                return Err(SamlError::UnsupportedBinding { binding });
            }
        };
        Ok(BindingContext {
            id,
            context,
            relay_state,
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature,
            sig_alg: sig_alg_out,
        })
    }

    #[cfg(not(crypto))]
    fn signed_request_context(
        &self,
        _binding: Binding,
        _xml: &str,
        _destination: String,
        _relay_state: Option<String>,
        _id: String,
    ) -> Result<BindingContext, SamlError> {
        Err(SamlError::Unsupported(
            "signing AuthnRequest requires a crypto provider feature".into(),
        ))
    }

    pub(crate) fn decode_login_response<'a>(
        &self,
        binding: Binding,
        request: &'a HttpRequest,
    ) -> Result<ReceivedMessage<'a>, SamlError> {
        ReceivedMessage::decode(
            binding,
            ParserType::SamlResponse,
            request,
            self.setting.redirect_inflate_max_bytes,
            self.setting.xml_limits,
        )
    }

    pub(crate) fn parse_unsolicited_login_response_at(
        &self,
        idp: &idp::Engine,
        received: ReceivedMessage<'_>,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        self.parse_login_response_inner_with_signature_evidence(
            idp,
            received,
            LoginResponseCorrelation::Unsolicited,
            options,
        )
    }

    pub(crate) fn parse_login_response_with_request_id_at(
        &self,
        idp: &idp::Engine,
        received: ReceivedMessage<'_>,
        request_id: &str,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        if request_id.is_empty() {
            return Err(SamlError::InvalidInResponseTo);
        }
        self.parse_login_response_inner_with_signature_evidence(
            idp,
            received,
            LoginResponseCorrelation::MessageId(request_id),
            options,
        )
    }

    fn parse_login_response_inner_with_signature_evidence(
        &self,
        idp: &idp::Engine,
        received: ReceivedMessage<'_>,
        correlation: LoginResponseCorrelation<'_>,
        options: LoginResponseParseOptions<'_>,
    ) -> Result<FlowResultWithSignatureEvidence, SamlError> {
        let binding = received.binding();
        let signing_certs = idp
            .metadata
            .as_metadata()
            .x509_certificates(CertUse::Signing);
        let audience = self.entity_id();
        let expected_in_response_to = match correlation {
            LoginResponseCorrelation::MessageId(request_id) => Some(request_id),
            LoginResponseCorrelation::Unsolicited => None,
        };
        let recipient = match options.expected_recipient {
            Some(recipient) => recipient.to_string(),
            None => self
                .metadata
                .assertion_consumer_location(binding)
                .ok_or_else(|| SamlError::MissingMetadata("AssertionConsumerService".into()))?,
        };
        let result = validate_received_message(
            &FlowOptions {
                signature_check: SignatureCheck::Require,
                require_audience_restriction: self.setting.require_audience_restriction,
                xml_signatures: self.setting.xml_signatures,
                from_issuer: idp.metadata.as_metadata().entity_id(),
                signing_certs,
                hmac_secret: idp.setting.hmac_secret.as_ref(),
                decrypt_key: self.setting.enc_private_key.as_deref(),
                require_encrypted_assertions: self.setting.is_assertion_encrypted,
                decrypt_key_pass: self.setting.enc_private_key_pass.as_deref(),
                additional_decrypt_keys: &self.setting.additional_decryption_keys,
                assertion_elements: self.setting.assertion_element_encryption,
                allow_rsa15_key_transport_decryption: self
                    .setting
                    .allow_rsa15_key_transport_decryption,
                max_decryption_work: self.setting.max_decryption_work,
                clock_skew: options.clock_skew,
                now: options.now,
                redirect_inflate_max_bytes: self.setting.redirect_inflate_max_bytes,
                xml_limits: self.setting.xml_limits,
                schema_validator: self.setting.schema_validator,
                expected_audience: Some(audience.as_str()),
                expected_in_response_to,
                ..FlowOptions::new(binding, ParserType::SamlResponse)
            },
            received,
            Some(recipient.as_str()),
            if self.setting.want_assertions_signed {
                AssertionSignatureRequirement::Direct
            } else {
                AssertionSignatureRequirement::Compatible
            },
            if self.setting.want_message_signed {
                ResponseSignatureRequirement::Required
            } else if self.setting.want_encrypted_cbc_response_signed {
                ResponseSignatureRequirement::RequiredForEncryptedCbc
            } else {
                ResponseSignatureRequirement::Optional
            },
            options.signed_destination,
        )?;
        if let LoginResponseCorrelation::Unsolicited = correlation {
            let in_response_to = result
                .extract()
                .get_str(crate::xml::fields::response::IN_RESPONSE_TO);
            if in_response_to.is_some() {
                return Err(SamlError::in_response_to_mismatch(None, in_response_to));
            }
            reject_unsolicited_bearer_in_response_to(
                result.saml_content(),
                self.setting.xml_limits,
            )?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{decode_base64, deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
    use crate::metadata::{Endpoint, IdpMetadataInput};
    use crate::tests::engine::SpMessages;
    use url::Url;

    fn unsigned_idp() -> Result<idp::Engine, SamlError> {
        idp::Engine::from_config(
            &IdpMetadataInput {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![
                    Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
                    Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
                ],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    fn unsigned_sp() -> Result<Engine, SamlError> {
        Engine::from_config(
            &SpMetadataInput {
                entity_id: "https://sp.example.com/metadata".into(),
                assertion_consumer_service: vec![Endpoint::new(
                    Binding::Post,
                    "https://sp.example.com/acs",
                )],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn create_unsigned_login_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = unsigned_sp()?.create_login_request(
            &unsigned_idp()?,
            Binding::Redirect,
            &LoginRequestOptions::default(),
        )?;
        let url = Url::parse(&ctx.context)?;
        let (_, value) = url
            .query_pairs()
            .find(|(k, _)| k == "SAMLRequest")
            .ok_or("missing SAMLRequest")?;
        let xml = String::from_utf8(deflate_raw_decode(
            &decode_base64(&value)?,
            MAX_DEFLATE_RAW_DECODE_BYTES,
        )?)?;
        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
        assert!(url.query_pairs().all(|(k, _)| k != "Signature"));
        Ok(())
    }

    #[test]
    fn create_unsigned_login_request_post_is_base64() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = unsigned_sp()?.create_login_request(
            &unsigned_idp()?,
            Binding::Post,
            &LoginRequestOptions::default(),
        )?;
        let xml = String::from_utf8(decode_base64(&ctx.context)?)?;
        assert!(xml.starts_with("<samlp:AuthnRequest"));
        Ok(())
    }
}

#[cfg(all(test, crypto))]
mod crypto_tests {
    use super::*;
    use crate::binding::decode_base64;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::crypto::verify_signature;
    use crate::entity::User;
    use crate::idp::LoginResponseOptions;
    use crate::metadata::{Endpoint, IdpMetadataInput};
    use crate::tests::engine::{IdpMessages, SpMessages};

    const IDP_CERT: &str = include_str!("../tests/fixtures/key/idp/cert.cer");
    const SP_PRIVKEY: &str = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    const SP_SIGNING_CERT: &str =
        include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");

    fn signing_idp() -> Result<idp::Engine, SamlError> {
        idp::Engine::from_config(
            &IdpMetadataInput {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![IDP_CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![
                    Endpoint::new(Binding::Redirect, "https://idp/sso"),
                    Endpoint::new(Binding::Post, "https://idp/sso"),
                ],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn parse_signed_response_extracts_name_id() -> Result<(), Box<dyn std::error::Error>> {
        let idp = idp::Engine::from_config(
            &IdpMetadataInput {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![SP_SIGNING_CERT.into()],
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let sp = Engine::from_config(
            &SpMetadataInput {
                entity_id: "https://sp.example.com/metadata".into(),
                assertion_consumer_service: vec![Endpoint::new(
                    Binding::Post,
                    "http://sp.example.com/demo1/index.php?acs",
                )],
                ..Default::default()
            },
            EntitySetting::default(),
        )?;
        let request_id = "_41e758fee373d51639552c4b040b1090e97f6685";
        let name_id = "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7";
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new(name_id),
            &LoginResponseOptions {
                in_response_to: Some(request_id),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let result =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, request_id)?;
        assert_eq!(result.extract.get_str("nameID"), Some(name_id));
        Ok(())
    }

    #[test]
    fn create_signed_post_request_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let sp = Engine::from_config(
            &SpMetadataInput {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let ctx = sp.create_login_request(
            &signing_idp()?,
            Binding::Post,
            &LoginRequestOptions::default(),
        )?;
        let signed_xml = String::from_utf8(decode_base64(&ctx.context)?)?;
        let (verified, _) = verify_signature(&signed_xml, &[SP_SIGNING_CERT.to_string()])?;
        assert!(
            verified,
            "signed AuthnRequest should verify with the SP cert"
        );
        Ok(())
    }

    #[test]
    fn create_signed_redirect_request_has_signature() -> Result<(), Box<dyn std::error::Error>> {
        let sp = Engine::from_config(
            &SpMetadataInput {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let ctx = sp.create_login_request(
            &signing_idp()?,
            Binding::Redirect,
            &LoginRequestOptions::default(),
        )?;
        assert!(ctx.context.contains("&SigAlg="));
        assert!(ctx.context.contains("&Signature="));
        Ok(())
    }
}
