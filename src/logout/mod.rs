//! Single Logout (SLO): create and parse LogoutRequest and LogoutResponse.

mod creation;
mod encrypted_id;
mod parsing;
mod rendering;

#[cfg(test)]
mod tests;

pub(crate) use creation::{
    create_logout_request_for_subject_inner, create_logout_response_inner, reject_soap_relay_state,
    LogoutRequestInput, LogoutRequestValidation, LogoutResponseInput,
};
pub(crate) use encrypted_id::decrypt_encrypted_id;
pub(crate) use parsing::{
    parse_logout_request_at, parse_logout_response_at, LogoutFlowValidation, LogoutReceipt,
};
pub(crate) use rendering::LogoutRequestSubject;
#[cfg(test)]
pub(crate) use rendering::{issuer_of, render_logout_request, LogoutRequestTimeAttributes};
