use super::{Engine, LoginResponseOptions, LoginResponseOverrides, RenderedLoginResponse};
use crate::constants::Binding;
use crate::entity::User;
use crate::error::SamlError;
use crate::sp;

impl Engine {
    pub(crate) fn render_posted_sso_response(
        &self,
        sp: &sp::Engine,
        user: &User,
        in_response_to: Option<&str>,
        overrides: LoginResponseOverrides<'_>,
    ) -> Result<RenderedLoginResponse, SamlError> {
        let issued = self.create_login_response_with_overrides(
            sp,
            Binding::Post,
            user,
            &LoginResponseOptions {
                in_response_to,
                relay_state: None,
            },
            overrides,
        )?;
        let xml = crate::binding::decode_base64(&issued.context.context)?;
        let xml = crate::xml::decode_utf8(xml)?;
        Ok(RenderedLoginResponse {
            id: issued.context.id,
            xml,
            session_index: issued.session_index,
        })
    }
}
