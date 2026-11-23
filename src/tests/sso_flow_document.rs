use saml_rs::flow::FlowResult;
use saml_rs::util::Value;
use saml_rs::xml::fields::login_response::{ASSERTION_ID, AUTHN_STATEMENTS};

const AUTHN_STATEMENT_XML: &str = "<saml:AuthnStatement><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";

pub(crate) fn set_authn_statements(flow: &mut FlowResult, statements: Value) {
    let count = match &statements {
        Value::Array(values) => values.len(),
        Value::Object(_) => 1,
        Value::Null | Value::Str(_) => 0,
    };
    let assertion_id = flow.extract.get_str(ASSERTION_ID).unwrap_or_default();
    flow.saml_content = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion ID="{assertion_id}">{}</saml:Assertion></samlp:Response>"#,
        AUTHN_STATEMENT_XML.repeat(count)
    );
    flow.extract.insert(AUTHN_STATEMENTS, statements);
}
