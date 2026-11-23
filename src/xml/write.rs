//! Structured XML writing helpers for generated SAML protocol XML.

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::model::Status;
use crate::xml::name::validate_namespace_prefix;

pub(crate) fn validate_tag_prefixes(
    protocol_prefix: &str,
    assertion_prefix: &str,
) -> Result<(), SamlError> {
    validate_namespace_prefix("protocol tag prefix", protocol_prefix)?;
    validate_namespace_prefix("assertion tag prefix", assertion_prefix)?;
    if protocol_prefix == assertion_prefix {
        return Err(SamlError::Invalid(
            "protocol and assertion tag prefixes must differ".into(),
        ));
    }
    Ok(())
}

/// Namespace prefixes for the protocol and assertion elements.
#[derive(Clone, Copy)]
pub(crate) struct Prefixes<'a> {
    protocol: &'a str,
    assertion: &'a str,
}

impl<'a> Prefixes<'a> {
    pub(crate) fn of(setting: &'a EntitySetting) -> Result<Self, SamlError> {
        validate_tag_prefixes(&setting.tag_prefix_protocol, &setting.tag_prefix_assertion)?;
        Ok(Self {
            protocol: &setting.tag_prefix_protocol,
            assertion: &setting.tag_prefix_assertion,
        })
    }

    pub(crate) fn xmlns_protocol(&self) -> String {
        format!("xmlns:{}", self.protocol)
    }

    pub(crate) fn xmlns_assertion(&self) -> String {
        format!("xmlns:{}", self.assertion)
    }

    pub(crate) fn assertion_prefix(&self) -> &str {
        self.assertion
    }

    pub(crate) fn protocol(&self, local: &str) -> String {
        format!("{}:{local}", self.protocol)
    }

    pub(crate) fn assertion(&self, local: &str) -> String {
        format!("{}:{local}", self.assertion)
    }
}

pub(crate) struct XmlWriter {
    inner: Writer<Vec<u8>>,
}

impl XmlWriter {
    pub(crate) fn new() -> Self {
        Self {
            inner: Writer::new(Vec::new()),
        }
    }

    pub(crate) fn finish(self) -> String {
        match String::from_utf8(self.inner.into_inner()) {
            Ok(xml) => xml,
            Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
        }
    }

    pub(crate) fn start<'a>(&mut self, name: &'a str, attrs: &[(&'a str, &'a str)]) {
        let elem = element(name, attrs);
        self.write(Event::Start(elem));
    }

    pub(crate) fn end(&mut self, name: &str) {
        self.write(Event::End(BytesEnd::new(name)));
    }

    pub(crate) fn empty<'a>(&mut self, name: &'a str, attrs: &[(&'a str, &'a str)]) {
        let elem = element(name, attrs);
        self.write(Event::Empty(elem));
    }

    pub(crate) fn status(
        &mut self,
        prefixes: &Prefixes<'_>,
        status: &Status,
        message: Option<&str>,
    ) {
        let status_name = prefixes.protocol("Status");
        let code = prefixes.protocol("StatusCode");
        let top_level = [("Value", status.top_level().as_uri())];
        self.start(&status_name, &[]);
        if let Some(subordinate) = status.subordinate() {
            self.start(&code, &top_level);
            self.empty(&code, &[("Value", subordinate.as_uri())]);
            self.end(&code);
        } else {
            self.empty(&code, &top_level);
        }
        if let Some(message) = message {
            self.text_element(&prefixes.protocol("StatusMessage"), &[], message);
        }
        self.end(&status_name);
    }

    pub(crate) fn text(&mut self, text: &str) {
        self.write(Event::Text(BytesText::new(text)));
    }

    pub(crate) fn raw(&mut self, xml: &str) {
        self.inner.get_mut().extend_from_slice(xml.as_bytes());
    }

    pub(crate) fn text_element<'a>(
        &mut self,
        name: &'a str,
        attrs: &[(&'a str, &'a str)],
        text: &str,
    ) {
        self.start(name, attrs);
        self.text(text);
        self.end(name);
    }

    fn write<'a>(&mut self, event: Event<'a>) {
        // Vec-backed writes cannot fail; quick-xml keeps the Result because the
        // same API supports arbitrary std::io::Write targets.
        let _ = self.inner.write_event(event);
    }
}

fn element<'a>(name: &'a str, attrs: &[(&'a str, &'a str)]) -> BytesStart<'a> {
    let mut elem = BytesStart::new(name);
    for attr in attrs {
        elem.push_attribute(*attr);
    }
    elem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_values_are_escaped() {
        let mut writer = XmlWriter::new();
        writer.empty("e", &[("n", "a\"b&c")]);
        assert_eq!(writer.finish(), "<e n=\"a&quot;b&amp;c\"/>");
    }
}
