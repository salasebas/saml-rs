use std::{
    env::{self, VarError},
    error::Error,
    fs,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum_sp::{Config, IdpLogoutTransport};
use saml_rs::InMemoryReplayCache;
use url::Url;

const EXAMPLE_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    let config = Config {
        public_base_url: Url::parse(&setting("SP_PUBLIC_BASE_URL", "http://localhost:3000/")?)?,
        idp_entity_id: setting("IDP_ENTITY_ID", "http://127.0.0.1:8080/realms/saml-rs")?,
        idp_metadata_xml: read_file("IDP_METADATA_FILE", "keycloak/idp-metadata.xml")?,
        sp_certificate_pem: read_file("SP_CERTIFICATE_FILE", "keys/sp-cert.pem")?,
        sp_private_key_pem: read_file("SP_PRIVATE_KEY_FILE", "keys/sp-key.pem")?,
        max_session_lifetime: Duration::from_secs(
            setting("SESSION_MAX_LIFETIME_SECONDS", "28800")?.parse()?,
        ),
        idp_logout_transport: match setting("IDP_LOGOUT_ALLOW_HTTP", "true")?.as_str() {
            "true" => IdpLogoutTransport::AllowHttp,
            "false" => IdpLogoutTransport::HttpsOnly,
            other => {
                return Err(format!("IDP_LOGOUT_ALLOW_HTTP is {other:?}, not true or false").into())
            }
        },
    };
    let listen_address = setting("LISTEN_ADDRESS", "127.0.0.1:3000")?;

    let replay_cache = Arc::new(Mutex::new(InMemoryReplayCache::new()));
    let app = axum_sp::router(config, Arc::new(SystemTime::now), replay_cache)?;
    let listener = tokio::net::TcpListener::bind(&listen_address).await?;
    tracing::info!(listen_address, "serving");
    axum::serve(listener, app).await?;
    Ok(())
}

fn setting(name: &str, default: &str) -> Result<String, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(VarError::NotPresent) => Ok(default.to_owned()),
        Err(error @ VarError::NotUnicode(_)) => Err(format!("{name}: {error}").into()),
    }
}

fn read_file(name: &str, default_in_example: &str) -> Result<String, Box<dyn Error>> {
    let path = setting(name, &format!("{EXAMPLE_DIR}/{default_in_example}"))?;
    fs::read_to_string(&path).map_err(|error| format!("{name} ({path}): {error}").into())
}
