use super::{
    descriptors, idp_config_builder, logout_request_input, logout_response_input,
    signed_authn_request_idp_validation, signing_sp_validation, sp_config_builder, subject,
    validation, LocalSloRole, LOCAL_SLO_ROLES,
};
use saml_rs::error::SignatureVerificationReason;
use saml_rs::{
    AlgorithmPolicy, Credentials, HmacSecret, IdentityProvider, LogoutBinding, RespondSlo,
    SamlError, ServiceProvider, SignatureAlgorithm, StartSlo, Status,
};

#[test]
fn receive_and_finish_use_only_the_peer_hmac_secret() -> Result<(), Box<dyn std::error::Error>> {
    for (sp_secret, idp_secret) in [
        (
            b"service-provider-hmac-secret".as_slice(),
            b"identity-provider-hmac-secret".as_slice(),
        ),
        (
            b"shared-provider-hmac-secret".as_slice(),
            b"shared-provider-hmac-secret".as_slice(),
        ),
    ] {
        let hmac = AlgorithmPolicy {
            signature: SignatureAlgorithm::HmacSha1,
            ..AlgorithmPolicy::default()
        };
        let sp = ServiceProvider::new(
            sp_config_builder(signing_sp_validation())?
                .algorithms(hmac.clone())
                .credentials(
                    Credentials::default().with_hmac_secret(HmacSecret::try_new(sp_secret)?),
                )
                .build()?,
        );
        let idp = IdentityProvider::new(
            idp_config_builder(signed_authn_request_idp_validation())?
                .algorithms(hmac)
                .credentials(
                    Credentials::default().with_hmac_secret(HmacSecret::try_new(idp_secret)?),
                )
                .build()?,
        );
        let (sp_missing, idp_missing) = descriptors(&sp, &idp)?;
        let sp_wrong = sp_missing
            .clone()
            .with_hmac_secret(HmacSecret::try_new(b"incorrect-hmac-secret")?);
        let idp_wrong = idp_missing
            .clone()
            .with_hmac_secret(HmacSecret::try_new(b"incorrect-hmac-secret")?);
        let sp_peer = sp_missing
            .clone()
            .with_hmac_secret(HmacSecret::try_new(sp_secret)?);
        let idp_peer = idp_missing
            .clone()
            .with_hmac_secret(HmacSecret::try_new(idp_secret)?);
        for sender in LOCAL_SLO_ROLES {
            let started = match sender {
                LocalSloRole::Sp => sp.start_slo(&idp_peer, subject()?, StartSlo::redirect())?,
                LocalSloRole::Idp => idp.start_slo(&sp_peer, subject()?, StartSlo::redirect())?,
            };
            for (sp_peer, idp_peer) in [(&sp_wrong, &idp_wrong), (&sp_missing, &idp_missing)] {
                let input = logout_request_input(&started.outbound, LogoutBinding::Redirect)?;
                let result = match sender {
                    LocalSloRole::Sp => idp.receive_slo(sp_peer, input, validation()),
                    LocalSloRole::Idp => sp.receive_slo(idp_peer, input, validation()),
                };
                assert!(
                    matches!(
                        result,
                        Err(SamlError::SignatureVerification {
                            reason: SignatureVerificationReason::BindingSignature,
                        })
                    ),
                    "{sender:?}: {result:?}"
                );
            }
            let input = logout_request_input(&started.outbound, LogoutBinding::Redirect)?;
            let received = match sender {
                LocalSloRole::Sp => idp.receive_slo(&sp_peer, input, validation())?,
                LocalSloRole::Idp => sp.receive_slo(&idp_peer, input, validation())?,
            };
            assert_eq!(received.message().name_id(), Some(subject()?.name_id()));
            let response = match sender {
                LocalSloRole::Sp => idp.respond_slo(
                    &sp_peer,
                    &received,
                    &Status::success(),
                    RespondSlo::redirect(),
                )?,
                LocalSloRole::Idp => sp.respond_slo(
                    &idp_peer,
                    &received,
                    &Status::success(),
                    RespondSlo::redirect(),
                )?,
            };
            for (sp_peer, idp_peer) in [(&sp_wrong, &idp_wrong), (&sp_missing, &idp_missing)] {
                let input = logout_response_input(&response, LogoutBinding::Redirect)?;
                let result = match sender {
                    LocalSloRole::Sp => {
                        sp.finish_slo(idp_peer, &started.pending, input, validation())
                    }
                    LocalSloRole::Idp => {
                        idp.finish_slo(sp_peer, &started.pending, input, validation())
                    }
                };
                assert!(
                    matches!(
                        result,
                        Err(SamlError::SignatureVerification {
                            reason: SignatureVerificationReason::BindingSignature,
                        })
                    ),
                    "{sender:?}: {result:?}"
                );
            }
            let input = logout_response_input(&response, LogoutBinding::Redirect)?;
            let completed = match sender {
                LocalSloRole::Sp => {
                    sp.finish_slo(&idp_peer, &started.pending, input, validation())?
                }
                LocalSloRole::Idp => {
                    idp.finish_slo(&sp_peer, &started.pending, input, validation())?
                }
            };
            assert_eq!(completed.peer_entity_id(), started.pending.peer_entity_id());
        }
    }
    Ok(())
}
