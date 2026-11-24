use crate::error::SamlError;

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
