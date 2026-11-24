mod deflate;
mod encoding;
mod escape;
mod parameters;
mod query;
mod redirect;
mod signed_message;
#[cfg(crypto)]
mod signing;
mod simplesign;

#[cfg(crypto)]
pub(crate) use signing::sign_detached_message;

#[cfg(test)]
pub(crate) use deflate::deflate_raw_encode;
pub(crate) use deflate::{deflate_raw_decode, MAX_DEFLATE_RAW_DECODE_BYTES};
pub(crate) use encoding::{decode_base64, decode_base64_with_limit, encode_base64};
#[cfg(any(crypto, test))]
pub(crate) use escape::xml_escape;
pub(crate) use parameters::single_parameter;
pub(crate) use query::{
    saml_query_params, SamlQueryParam, ARTIFACT_PARAMETERS, REDIRECT_MESSAGE_PARAMETERS,
};
#[cfg(crypto)]
pub(crate) use redirect::append_signature;
#[cfg(any(crypto, test))]
pub(crate) use redirect::build_redirect_octet;
pub(crate) use redirect::build_redirect_url;
pub(crate) use redirect::{append_redirect_query, redirect_binding_query};
pub(crate) use signed_message::{sign_message, sign_soap_message};
pub(crate) use simplesign::build_simplesign_octet;
