use crate::constants::url_params;
use crate::error::SamlError;

pub(crate) const REDIRECT_MESSAGE_PARAMETERS: &[&str] = &[
    url_params::SAML_REQUEST,
    url_params::SAML_RESPONSE,
    url_params::RELAY_STATE,
    url_params::SIG_ALG,
    url_params::SIGNATURE,
    url_params::SAML_ENCODING,
];

pub(crate) const ARTIFACT_PARAMETERS: &[&str] = &[url_params::SAML_ART, url_params::RELAY_STATE];

const SAML_PARAMETERS: &[&str] = &[
    url_params::SAML_REQUEST,
    url_params::SAML_RESPONSE,
    url_params::SAML_ART,
    url_params::RELAY_STATE,
    url_params::SIG_ALG,
    url_params::SIGNATURE,
    url_params::SAML_ENCODING,
];

pub(crate) struct SamlQueryParam<'a> {
    pub(crate) name: &'static str,
    pub(crate) encoded_value: &'a str,
    pub(crate) value: String,
}

pub(crate) fn saml_query_params<'a>(
    raw_query: &'a str,
    names: &[&'static str],
) -> Result<Vec<SamlQueryParam<'a>>, SamlError> {
    query_segments(raw_query)
        .filter_map(|(name, encoded_value)| {
            parameter_name(name, names).map(|name| {
                let value = String::from_utf8(form_decode(encoded_value))
                    .map_err(|_| SamlError::Invalid(format!("{name} parameter is not UTF-8")))?;
                Ok(SamlQueryParam {
                    name,
                    encoded_value,
                    value,
                })
            })
        })
        .collect()
}

pub(crate) fn ensure_endpoint_query_has_no_saml_parameter(
    endpoint_query: &str,
) -> Result<(), SamlError> {
    match query_segments(endpoint_query).find_map(|(name, _)| parameter_name(name, SAML_PARAMETERS))
    {
        Some(name) => Err(SamlError::Invalid(format!(
            "Redirect endpoint query already has the SAML parameter {name}"
        ))),
        None => Ok(()),
    }
}

fn query_segments(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .trim_start_matches('?')
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.split_once('=').unwrap_or((segment, "")))
}

fn parameter_name(encoded_name: &str, names: &[&'static str]) -> Option<&'static str> {
    let name = form_decode(encoded_name);
    names
        .iter()
        .copied()
        .find(|candidate| candidate.as_bytes() == name)
}

fn form_decode(encoded: &str) -> Vec<u8> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = match (byte, bytes.get(index + 1..index + 3)) {
            (b'%', Some(&[high, low])) => hex_value(high).zip(hex_value(low)),
            _ => None,
        };
        match (escaped, byte) {
            (Some((high, low)), _) => {
                decoded.push((high << 4) | low);
                index += 3;
            }
            (None, b'+') => {
                decoded.push(b' ');
                index += 1;
            }
            (None, _) => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    decoded
}

fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decode_matches_the_urlencoded_parser() {
        for encoded in [
            "a+b%2Bc",
            "%41%4a%zz%",
            "%",
            "%4",
            "caf%C3%A9",
            "%E9",
            "%0A%0d",
        ] {
            let expected: Vec<u8> = url::form_urlencoded::parse(format!("x={encoded}").as_bytes())
                .map(|(_, value)| value.into_owned().into_bytes())
                .next()
                .unwrap_or_default();
            let decoded = form_decode(encoded);
            match String::from_utf8(decoded.clone()) {
                Ok(text) => assert_eq!(text.into_bytes(), expected, "{encoded}"),
                Err(_) => assert_eq!(
                    String::from_utf8_lossy(&decoded).into_owned().into_bytes(),
                    expected,
                    "{encoded}"
                ),
            }
        }
    }
}
