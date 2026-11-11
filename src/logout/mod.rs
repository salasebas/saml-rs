//! Single Logout (SLO): create and parse LogoutRequest and LogoutResponse.

mod bindings;
mod creation;
mod encrypted_id;
mod parsing;
mod rendering;
mod signing;

#[cfg(test)]
mod tests;

pub use creation::{
    create_logout_request, create_logout_request_with_id, create_logout_response,
    create_logout_response_with_id,
};
pub(crate) use creation::{
    create_logout_request_with_session_indexes, create_logout_response_with_status,
    LogoutRequestSessionIndexes, LogoutRequestValidation,
};
pub(crate) use encrypted_id::decrypt_encrypted_id;
pub use parsing::{
    parse_logout_request, parse_logout_response, parse_logout_response_without_request_id,
};
pub(crate) use parsing::{
    parse_logout_request_at, parse_logout_response_at, LogoutFlowValidation, LogoutReceipt,
};
pub(crate) use signing::sign_browser_message;
