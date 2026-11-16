use saml_rs::binding::{
    deflate_raw_decode, deflate_raw_encode, saml_post_binding_form, xml_escape,
};
use saml_rs::constants::Binding;
use saml_rs::entity::BindingContext;
use saml_rs::SamlError;

fn form_action(form: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let (_, rest) = form
        .split_once("<form method=\"post\" action=\"")
        .ok_or("missing form action")?;
    let (action, _) = rest.split_once("\">").ok_or("unterminated form action")?;
    Ok(action)
}

fn hidden_fields(form: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut fields = Vec::new();
    let mut rest = form;
    while let Some((_, after_marker)) = rest.split_once("<input type=\"hidden\" name=\"") {
        let (name, after_name) = after_marker
            .split_once("\" value=\"")
            .ok_or("unterminated hidden input name")?;
        let (value, after_value) = after_name
            .split_once("\"/>")
            .ok_or("unterminated hidden input value")?;
        fields.push((name.to_string(), value.to_string()));
        rest = after_value;
    }
    Ok(fields)
}

fn hidden_field_value<'a>(
    fields: &'a [(String, String)],
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    fields
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("missing hidden field {name}").into())
}

#[test]
fn deflate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let original = b"<samlp:AuthnRequest ID=\"_abc\" Version=\"2.0\"/>";
    let compressed = deflate_raw_encode(original)?;
    let restored = deflate_raw_decode(&compressed)?;
    assert_eq!(restored, original);
    Ok(())
}

#[test]
fn xml_escape_golden() {
    assert_eq!(
        xml_escape("a & b <c> \"d\" 'e'"),
        "a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"
    );
}

#[test]
fn post_form_renders_escaped_action_and_hidden_fields() -> Result<(), Box<dyn std::error::Error>> {
    let form = saml_post_binding_form(
        "https://idp.example.org/acs?next=1&label=\"<'",
        "SAMLResponse",
        "PHNhbWxwOlJlc3BvbnNlLz4=&<script>\"'",
        Some("relay=&<>\"'<script>"),
    )?;

    assert_eq!(
        form_action(&form)?,
        "https://idp.example.org/acs?next=1&amp;label=&quot;&lt;&#39;"
    );
    assert_eq!(
        hidden_fields(&form)?,
        vec![
            (
                "SAMLResponse".to_string(),
                "PHNhbWxwOlJlc3BvbnNlLz4=&amp;&lt;script&gt;&quot;&#39;".to_string(),
            ),
            (
                "RelayState".to_string(),
                "relay=&amp;&lt;&gt;&quot;&#39;&lt;script&gt;".to_string(),
            ),
        ]
    );

    assert!(!form.contains("<script>"));
    Ok(())
}

#[test]
fn post_form_escapes_param_name() -> Result<(), Box<dyn std::error::Error>> {
    let form = saml_post_binding_form(
        "https://idp.example.org/acs",
        "SAML<Response>&\"'",
        "payload",
        None,
    )?;

    assert_eq!(
        hidden_fields(&form)?,
        vec![(
            "SAML&lt;Response&gt;&amp;&quot;&#39;".to_string(),
            "payload".to_string(),
        )]
    );
    Ok(())
}

#[test]
fn binding_context_post_form_renders_simplesign_fields_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = BindingContext {
        id: "_id".into(),
        context: "PHNhbWxwOlJlc3BvbnNlLz4=".into(),
        relay_state: Some("relay=&<>\"'".into()),
        entity_endpoint: "https://idp.example.org/sso".into(),
        binding: Binding::SimpleSign,
        request_type: "SAMLRequest",
        signature: Some("sig=&<>\"'".into()),
        sig_alg: Some("alg=&<>\"'".into()),
    };

    let form = context.post_form()?;
    let fields = hidden_fields(&form)?;

    assert_eq!(
        hidden_field_value(&fields, "SAMLRequest")?,
        "PHNhbWxwOlJlc3BvbnNlLz4="
    );
    assert_eq!(
        hidden_field_value(&fields, "RelayState")?,
        "relay=&amp;&lt;&gt;&quot;&#39;"
    );
    assert_eq!(
        hidden_field_value(&fields, "SigAlg")?,
        "alg=&amp;&lt;&gt;&quot;&#39;"
    );
    assert_eq!(
        hidden_field_value(&fields, "Signature")?,
        "sig=&amp;&lt;&gt;&quot;&#39;"
    );
    assert!(!form.contains("<script>"));
    Ok(())
}

#[test]
fn post_form_rejects_active_and_non_http_action_urls() {
    for action in [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "ftp://idp.example.org/acs",
        "idp.example.org/acs",
        "/saml/acs",
    ] {
        let result = saml_post_binding_form(action, "SAMLResponse", "payload", None);

        assert!(
            matches!(
                &result,
                Err(SamlError::Invalid(message))
                    if message == "ERR_UNSAFE_POST_BINDING_ACTION_URL"
            ),
            "unexpected result for {action}: {result:?}"
        );
    }
}

#[test]
fn binding_context_post_form_rejects_active_endpoint() {
    let context = BindingContext {
        id: "_id".into(),
        context: "PHNhbWxwOlJlc3BvbnNlLz4=".into(),
        relay_state: None,
        entity_endpoint: "javascript:alert(1)".into(),
        binding: Binding::Post,
        request_type: "SAMLResponse",
        signature: None,
        sig_alg: None,
    };

    let result = context.post_form();

    assert!(
        matches!(
            &result,
            Err(SamlError::Invalid(message)) if message == "ERR_UNSAFE_POST_BINDING_ACTION_URL"
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
fn binding_context_post_form_rejects_partial_signature_state() {
    let context = BindingContext {
        id: "_id".into(),
        context: "PHNhbWxwOlJlc3BvbnNlLz4=".into(),
        relay_state: None,
        entity_endpoint: "https://idp.example.org/sso".into(),
        binding: Binding::SimpleSign,
        request_type: "SAMLRequest",
        signature: Some("signature".into()),
        sig_alg: None,
    };

    let result = context.post_form();

    assert!(
        matches!(
            &result,
            Err(SamlError::Invalid(message)) if message == "ERR_PARTIAL_POST_BINDING_SIGNATURE"
        ),
        "unexpected result: {result:?}"
    );
}
