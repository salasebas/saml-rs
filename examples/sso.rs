//! End-to-end typed SSO: SP starts an `AuthnRequest`, the IdP receives it and
//! issues a signed `Response`, and the SP finishes with a typed session.
//!
//! Both peers generate their metadata in this process. For externally supplied metadata,
//! see `MetadataTrustPolicy::RequireSignature` for import with a pinned signing certificate.
//!
//! Run with: `cargo run -p saml-rs --example sso`
//! (the `crypto-bergshamra` feature is on by default).

#[cfg(crypto)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::{
        AcsEndpoint, CertificatePem, Credentials, EntityId, IdentityProvider, IdpConfig,
        IdpDescriptor, Inbound, MetadataTrustPolicy, NameId, NameIdFormat, PrivateKeyPem,
        RelayState, ReplayPolicy, RespondSso, SamlValidationContext, ServiceProvider, SpConfig,
        SpDescriptor, SsoAssertion, SsoEndpoint, StartSso, X509Credential,
    };
    use std::time::SystemTime;

    let privkey = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    let cert = include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    let credentials = || {
        Credentials::default().with_signing_credential(X509Credential::new(
            CertificatePem::new(cert),
            PrivateKeyPem::new(privkey),
        ))
    };
    let mut replay_cache = saml_rs::InMemoryReplayCache::new();
    let validation = || SamlValidationContext::new(SystemTime::now(), ReplayPolicy::Disabled);

    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .credentials(credentials())
        .build()?,
    );
    let idp = IdentityProvider::new(
        IdpConfig::builder(
            EntityId::try_new("https://idp.example.com/metadata")?,
            SsoEndpoint::post("https://idp.example.com/sso")?,
        )
        .credentials(credentials())
        .build()?,
    );

    let sp_descriptor = SpDescriptor::from_metadata_xml(
        EntityId::try_new("https://sp.example.com/metadata")?,
        sp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp.metadata_xml(),
        MetadataTrustPolicy::AllowUnsigned,
    )?;

    let relay_state = RelayState::try_new("demo-state")?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().relay_state(relay_state))?;
    println!(
        "SP  -> AuthnRequest id = {}",
        started.pending.request_id().as_str()
    );

    let request = idp.receive_sso(
        &sp_descriptor,
        Inbound::post(started.outbound.post_form()?.fields().to_vec()),
        validation(),
    )?;
    println!(
        "IdP <- request issuer  = {}",
        request.message().issuer().as_str()
    );

    let response = idp.respond_sso(
        &sp_descriptor,
        &request,
        SsoAssertion::new(NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress)),
        RespondSso::post(),
    )?;

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        Inbound::post(response.post_form()?.fields().to_vec()),
        SamlValidationContext::new(
            SystemTime::now(),
            ReplayPolicy::RequireCache(&mut replay_cache),
        ),
    );
    let session = session?;
    println!("SP  <- authenticated   = {}", session.name_id().value());
    Ok(())
}

#[cfg(not(crypto))]
fn main() {
    eprintln!("Enable a crypto provider feature (`crypto-bergshamra` is on by default).");
}
