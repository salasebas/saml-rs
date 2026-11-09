//! Common domain cookie for Identity Provider Discovery.

use std::net::Ipv4Addr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::SamlError;

const MAX_ENTITY_IDENTIFIER_CHARACTERS: usize = 1024;
const MAX_EXISTING_COOKIE_BYTES: usize = 8 * 1024;
const MAX_COOKIE_NAME_AND_VALUE_BYTES: usize = 4096;
const MAX_PERSISTENT_LIFETIME_SECONDS: u64 = 2_147_483_647;

/// How long the browser keeps the common domain cookie.
///
/// `Session` ends with the browser session. `Persistent` keeps the cookie for
/// `max_age`. Neither value means the principal still has a session with this
/// identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonDomainCookieLifetime {
    /// The browser drops the cookie when the session ends.
    Session,
    /// The browser keeps the cookie for `max_age`.
    ///
    /// `max_age` must be a whole number of seconds, at least one second, and
    /// at most 2147483647 seconds. That duration is written as `Max-Age`.
    Persistent {
        /// How long the browser keeps the cookie.
        max_age: Duration,
    },
}

/// What the caller passes to remember this identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RememberIdentityProvider<'a> {
    common_domain: &'a str,
    lifetime: CommonDomainCookieLifetime,
    existing_cookie: Option<&'a str>,
}

impl<'a> RememberIdentityProvider<'a> {
    /// Start a cookie list that contains only this identity provider.
    ///
    /// `common_domain` is the deployment common domain, without a leading
    /// period: `example.org` becomes the cookie domain `.example.org`.
    /// `lifetime` is the browser session, or a persistent `Max-Age`. Call
    /// [`Self::with_existing_cookie`] when the browser already sent
    /// `_saml_idp`.
    pub fn new(common_domain: &'a str, lifetime: CommonDomainCookieLifetime) -> Self {
        Self {
            common_domain,
            lifetime,
            existing_cookie: None,
        }
    }

    /// Keep the identity providers already listed in this `_saml_idp` value.
    ///
    /// An empty value starts a new list. Any other value is the cookie value:
    /// percent-encoded, or already decoded with a real space between entries.
    /// A `+` inside a base64 entry stays a `+`.
    pub fn with_existing_cookie(mut self, value: &'a str) -> Self {
        self.existing_cookie = Some(value);
        self
    }
}

/// `_saml_idp` cookie for the caller to write.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the caller writes this cookie on the common domain"]
pub struct CommonDomainCookie {
    value: String,
    domain: String,
    lifetime: CommonDomainCookieLifetime,
}

impl CommonDomainCookie {
    /// Cookie name required by the discovery profile.
    pub const NAME: &'static str = "_saml_idp";
    /// Cookie path required by the discovery profile.
    pub const PATH: &'static str = "/";

    /// `_saml_idp`.
    pub fn name(&self) -> &'static str {
        Self::NAME
    }

    /// URL-encoded list of base64 identity-provider entity identifiers.
    ///
    /// This identity provider is last.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// `/`.
    pub fn path(&self) -> &'static str {
        Self::PATH
    }

    /// Common domain with the required leading period.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The cookie is marked secure.
    pub fn secure(&self) -> bool {
        true
    }

    /// Session or persistent lifetime the caller asked for.
    pub fn lifetime(&self) -> CommonDomainCookieLifetime {
        self.lifetime
    }

    /// `Set-Cookie` header value, without the header name.
    ///
    /// The caller may append extra attributes, such as `SameSite`, after this
    /// value.
    pub fn set_cookie_header(&self) -> String {
        let mut header = format!(
            "{name}={value}; Path={path}; Domain={domain}; Secure",
            name = Self::NAME,
            value = self.value,
            path = Self::PATH,
            domain = self.domain,
        );
        if let CommonDomainCookieLifetime::Persistent { max_age } = self.lifetime {
            let seconds = max_age.as_secs();
            header.push_str(&format!("; Max-Age={seconds}"));
        }
        header
    }
}

pub(crate) fn remember_identity_provider(
    entity_id: &str,
    options: RememberIdentityProvider<'_>,
) -> Result<CommonDomainCookie, SamlError> {
    validate_entity_identifier(entity_id)?;
    let domain = common_domain_attribute(options.common_domain)?;
    let lifetime = validated_lifetime(options.lifetime)?;
    let mut entity_ids = entity_ids_from_existing(options.existing_cookie)?;
    entity_ids.retain(|existing| existing != entity_id);
    entity_ids.push(entity_id.to_string());
    let mut value = encode_cookie_value(&entity_ids);
    // The oldest entries are dropped until the cookie name and value together
    // are at most 4096 bytes.
    while CommonDomainCookie::NAME.len() + value.len() > MAX_COOKIE_NAME_AND_VALUE_BYTES
        && entity_ids.len() > 1
    {
        entity_ids.remove(0);
        value = encode_cookie_value(&entity_ids);
    }
    Ok(CommonDomainCookie {
        value,
        domain,
        lifetime,
    })
}

fn validate_entity_identifier(entity_id: &str) -> Result<(), SamlError> {
    if entity_id.len() > MAX_ENTITY_IDENTIFIER_CHARACTERS || !is_entity_identifier_uri(entity_id) {
        return Err(invalid(
            "entity identifier must be a URI of at most 1024 characters",
        ));
    }
    Ok(())
}

fn is_entity_identifier_uri(entity_id: &str) -> bool {
    // Every byte is a visible ASCII character.
    if !entity_id.bytes().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    let Some((scheme, rest)) = entity_id.split_once(':') else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    let Some(first) = scheme_chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && scheme_chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
        && !rest.is_empty()
}

fn common_domain_attribute(common_domain: &str) -> Result<String, SamlError> {
    if common_domain.is_empty() {
        return Err(invalid("common domain must not be empty"));
    }
    if common_domain.starts_with('.') {
        return Err(invalid("common domain is passed without a leading period"));
    }
    if !is_ascii_hostname(common_domain) {
        return Err(invalid("common domain must be an ASCII hostname"));
    }
    Ok(format!(".{common_domain}"))
}

fn is_ascii_hostname(domain: &str) -> bool {
    // An IPv4 literal is not a common domain.
    if domain.len() > 253 || domain.ends_with('.') || domain.parse::<Ipv4Addr>().is_ok() {
        return false;
    }
    domain.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

fn validated_lifetime(
    lifetime: CommonDomainCookieLifetime,
) -> Result<CommonDomainCookieLifetime, SamlError> {
    if let CommonDomainCookieLifetime::Persistent { max_age } = lifetime {
        if max_age.subsec_nanos() != 0 {
            return Err(invalid(
                "persistent discovery cookie lifetime must be a whole number of seconds",
            ));
        }
        if max_age.as_secs() == 0 {
            return Err(invalid(
                "persistent discovery cookie lifetime must be at least one second",
            ));
        }
        if max_age.as_secs() > MAX_PERSISTENT_LIFETIME_SECONDS {
            return Err(invalid(
                "persistent discovery cookie lifetime must be at most 2147483647 seconds",
            ));
        }
    }
    Ok(lifetime)
}

fn entity_ids_from_existing(existing: Option<&str>) -> Result<Vec<String>, SamlError> {
    let Some(existing) = existing.filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    if existing.len() > MAX_EXISTING_COOKIE_BYTES {
        return Err(invalid(
            "existing common domain cookie is larger than 8192 bytes",
        ));
    }
    let decoded = decode_percent(existing, PlusSign::Keep)?;
    match entity_ids_from_decoded(&decoded) {
        Ok(entity_ids) => Ok(entity_ids),
        Err(error) if !existing.as_bytes().contains(&b'+') => Err(error),
        Err(_) => {
            let form_decoded = decode_percent(existing, PlusSign::Space)?;
            entity_ids_from_decoded(&form_decoded)
        }
    }
}

fn entity_ids_from_decoded(decoded: &str) -> Result<Vec<String>, SamlError> {
    if decoded.is_empty() {
        return Ok(Vec::new());
    }
    decoded.split(' ').map(entity_id_from_token).collect()
}

fn entity_id_from_token(token: &str) -> Result<String, SamlError> {
    if token.is_empty() {
        return Err(invalid("existing common domain cookie has an empty entry"));
    }
    let bytes = STANDARD
        .decode(token)
        .map_err(|_| invalid("existing common domain cookie entry is not base64"))?;
    String::from_utf8(bytes)
        .map_err(|_| invalid("existing common domain cookie entry is not an entity identifier"))
}

fn encode_cookie_value(entity_ids: &[String]) -> String {
    let mut raw = String::new();
    for (index, entity_id) in entity_ids.iter().enumerate() {
        if index > 0 {
            raw.push(' ');
        }
        raw.push_str(&STANDARD.encode(entity_id.as_bytes()));
    }
    encode_percent(&raw)
}

fn encode_percent(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        ) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

enum PlusSign {
    Keep,
    Space,
}

fn decode_percent(value: &str, plus: PlusSign) -> Result<String, SamlError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' if matches!(plus, PlusSign::Space) => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let hex = bytes.get(index + 1..index + 3).ok_or_else(|| {
                    invalid("existing common domain cookie has a truncated percent escape")
                })?;
                let high = hex_value(hex[0])?;
                let low = hex_value(hex[1])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte if byte.is_ascii() => {
                decoded.push(byte);
                index += 1;
            }
            _ => {
                return Err(invalid(
                    "existing common domain cookie is not URL-encoded text",
                ));
            }
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| invalid("existing common domain cookie is not URL-encoded text"))
}

fn hex_value(byte: u8) -> Result<u8, SamlError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid(
            "existing common domain cookie has a percent escape that is not hexadecimal",
        )),
    }
}

fn invalid(message: &str) -> SamlError {
    SamlError::Invalid(message.to_string())
}
