//! Structured XML writing helpers for generated SAML metadata.

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

pub(super) struct MetadataWriter {
    inner: Writer<Vec<u8>>,
}

impl MetadataWriter {
    pub(super) fn new() -> Self {
        Self {
            inner: Writer::new(Vec::new()),
        }
    }

    pub(super) fn finish(self) -> String {
        match String::from_utf8(self.inner.into_inner()) {
            Ok(xml) => xml,
            Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
        }
    }

    pub(super) fn start<'a>(&mut self, name: &'a str, attrs: &[(&'a str, &'a str)]) {
        let elem = element(name, attrs);
        self.write(Event::Start(elem));
    }

    pub(super) fn end(&mut self, name: &str) {
        self.write(Event::End(BytesEnd::new(name)));
    }

    pub(super) fn empty<'a>(&mut self, name: &'a str, attrs: &[(&'a str, &'a str)]) {
        let elem = element(name, attrs);
        self.write(Event::Empty(elem));
    }

    pub(super) fn text_element(&mut self, name: &str, text: &str) {
        self.text_element_with_attrs(name, &[], text);
    }

    pub(super) fn text_element_with_attrs(
        &mut self,
        name: &str,
        attrs: &[(&str, &str)],
        text: &str,
    ) {
        self.start(name, attrs);
        self.write(Event::Text(BytesText::new(text)));
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
