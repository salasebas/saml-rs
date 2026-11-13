//! Low-level samlify-port SSO example on the raw API.
//!
//! `SpValidationPolicy::compatibility` is the typed name for keeping this
//! behavior on the builders. New browser integrations should start with
//! `examples/sso.rs`. This example is for callers that need direct access to
//! raw `ServiceProvider`, `IdentityProvider`, `HttpRequest`, or `FlowResult`
//! values.

#[cfg(crypto)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::constants::signature_algorithm::RSA_SHA256;
    use saml_rs::raw::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
    use saml_rs::raw::{
        Binding, EntitySetting, HttpRequest, IdentityProvider, LoginResponseOptions,
        ServiceProvider, User,
    };

    let privkey = include_str!("../tests/fixtures/key/sp/privkey.unencrypted.pkcs8.pem");
    let cert = include_str!("../tests/fixtures/key/sp/cert.unencrypted.pkcs8.cer");
    let signing = || {
        let mut setting = EntitySetting::default();
        setting.private_key = Some(privkey.into());
        setting.signing_cert = Some(cert.into());
        setting.request_signature_algorithm = RSA_SHA256.into();
        setting
    };

    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![cert.into()],
            want_authn_requests_signed: true,
            single_sign_on_service: vec![Endpoint::new(
                Binding::Post,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        },
        signing(),
    )?;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            authn_requests_signed: true,
            want_assertions_signed: true,
            signing_certs: vec![cert.into()],
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs",
            )],
            ..Default::default()
        },
        signing(),
    )?;

    let request = sp.create_login_request(&idp, Binding::Post, None)?;
    let parsed = idp.parse_login_request(
        &sp,
        Binding::Post,
        &HttpRequest::post(vec![("SAMLRequest".into(), request.context.clone())]),
    )?;
    let response = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("alice@example.com"),
        &LoginResponseOptions {
            in_response_to: parsed.extract.get_str("request.id"),
            ..Default::default()
        },
    )?;
    let result = sp.parse_login_response_with_request_id(
        &idp,
        Binding::Post,
        &HttpRequest::post(vec![("SAMLResponse".into(), response.context)]),
        &request.id,
    )?;
    println!(
        "samlify-port raw authenticated = {:?}",
        result.extract.get_str("nameID")
    );
    Ok(())
}

#[cfg(not(crypto))]
fn main() {
    eprintln!("Enable a crypto provider feature (`crypto-bergshamra` is on by default).");
}
