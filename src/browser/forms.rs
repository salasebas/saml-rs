use crate::model::EndpointUrl;

/// HTML form field emitted or consumed by browser POST bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    name: String,
    value: String,
}

impl FormField {
    /// Create a form field.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Field value.
    pub fn value(&self) -> &str {
        &self.value
    }

    pub(crate) fn into_pair(self) -> (String, String) {
        (self.name, self.value)
    }
}

/// Typed auto-submit POST form data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostForm {
    action: EndpointUrl,
    fields: Vec<FormField>,
}

impl PostForm {
    pub(crate) fn new(action: EndpointUrl, fields: Vec<FormField>) -> Self {
        Self { action, fields }
    }

    /// Form action URL.
    pub fn action(&self) -> &EndpointUrl {
        &self.action
    }

    /// Hidden fields.
    pub fn fields(&self) -> &[FormField] {
        &self.fields
    }

    /// Value of the hidden field named `name`, if the form has one.
    ///
    /// A form this crate builds has at most one field per name.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name() == name)
            .map(FormField::value)
    }
}
