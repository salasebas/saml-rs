//! Binding parameters read from a query string or form.

use crate::error::SamlError;

/// Value of the binding parameter `name`, which may occur at most once.
pub(crate) fn single_parameter<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    name: &'static str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = pairs
        .into_iter()
        .filter(|(candidate, _)| *candidate == name)
        .map(|(_, value)| value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::DuplicateBindingParameter { name });
    }
    Ok(first)
}
