use saml_rs::TemplatePolicy;

pub fn templates(protocol: &str, assertion: &str) -> TemplatePolicy {
    let mut policy = TemplatePolicy::default();
    policy.tag_prefix_protocol = protocol.into();
    policy.tag_prefix_assertion = assertion.into();
    policy
}
