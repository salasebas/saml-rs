//! HTTP header fields the SAML bindings ask a sender to include.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.

pub(crate) const CACHE_CONTROL: HttpHeader = HttpHeader::new("Cache-Control", "no-cache, no-store");
pub(crate) const PRAGMA: HttpHeader = HttpHeader::new("Pragma", "no-cache");

/// One HTTP header field to send with a SAML message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    name: &'static str,
    value: &'static str,
}

impl HttpHeader {
    pub(crate) const fn new(name: &'static str, value: &'static str) -> Self {
        Self { name, value }
    }

    /// Header field name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Header field value.
    pub fn value(&self) -> &str {
        self.value
    }
}
