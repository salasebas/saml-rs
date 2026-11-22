use base64::{engine::general_purpose::STANDARD, Engine};
use saml_rs::{FormField, Outbound};

pub fn unsigned_post_fields<Message>(
    outbound: &Outbound<Message>,
    field_name: &str,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    let form = outbound.post_form()?;
    let xml =
        String::from_utf8(STANDARD.decode(form.value(field_name).ok_or("missing POST field")?)?)?;
    let start = xml
        .find("<ds:Signature")
        .ok_or("signed POST message is missing ds:Signature")?;
    let end_rel = xml[start..]
        .find("</ds:Signature>")
        .ok_or("signed POST message has an unclosed ds:Signature")?;
    let end = start + end_rel + "</ds:Signature>".len();
    let unsigned = format!("{}{}", &xml[..start], &xml[end..]);
    assert!(!unsigned.contains("ds:Signature"));
    Ok(form
        .fields()
        .iter()
        .map(|field| {
            if field.name() == field_name {
                FormField::new(field_name, STANDARD.encode(unsigned.as_bytes()))
            } else {
                field.clone()
            }
        })
        .collect())
}
