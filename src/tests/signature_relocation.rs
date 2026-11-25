use crate::error::SamlError;
use crate::xml::dom::{self, Node};
use crate::XmlLimits;
use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Relocation {
    FirstChildOf,
    After,
}

// The enveloped-signature transform removes the signature wherever it sits
// inside the signed element, so a moved signature keeps a valid digest and
// signature value.
pub(crate) fn relocate_signature(
    signed: &str,
    path: &[&str],
    relocation: Relocation,
) -> Result<String, SamlError> {
    let root = dom::parse_document(signed, XmlLimits::default())?.root;
    let signature = root
        .child_named("Signature")
        .ok_or_else(|| SamlError::Invalid("the root has no direct Signature".into()))?;
    let signature_xml = &signed[signature.start..signature.end];
    let stripped = format!("{}{}", &signed[..signature.start], &signed[signature.end..]);
    let stripped_root = dom::parse_document(&stripped, XmlLimits::default())?.root;
    let anchor = resolve(&stripped_root, path)
        .ok_or_else(|| SamlError::Invalid(format!("no element at {path:?}")))?;
    let position = match relocation {
        Relocation::After => anchor.end,
        Relocation::FirstChildOf => {
            let mut reader = Reader::from_str(&stripped[anchor.start..anchor.end]);
            match reader.read_event().map_err(crate::error::xml_err)? {
                Event::Start(_) => {
                    anchor.start
                        + usize::try_from(reader.buffer_position())
                            .map_err(crate::error::xml_err)?
                }
                other => {
                    return Err(SamlError::Invalid(format!(
                        "the anchor has no start tag: {other:?}"
                    )))
                }
            }
        }
    };
    Ok(format!(
        "{}{signature_xml}{}",
        &stripped[..position],
        &stripped[position..]
    ))
}

fn resolve<'a>(node: &'a Node, path: &[&str]) -> Option<&'a Node> {
    let (&name, rest) = path.split_first()?;
    if node.local_name != name {
        return None;
    }
    match rest.first() {
        None => Some(node),
        Some(&child) => resolve(node.child_named(child)?, rest),
    }
}
