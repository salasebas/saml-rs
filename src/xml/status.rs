use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use quick_xml::XmlVersion;

use crate::constants::namespace;
use crate::error::{xml_err, SamlError};
use crate::model::Status;
use crate::xml::dom::{reader_err, XmlLimits};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    Root,
    Status,
    TopLevelCode,
    Other,
}

#[derive(Default)]
struct Shape {
    root: String,
    statuses: usize,
    top_level_codes: usize,
    top_level: Option<String>,
    subordinate_codes: usize,
    subordinate: Option<String>,
}

pub(crate) fn read_status(xml: &str, limits: XmlLimits) -> Result<Status, SamlError> {
    limits.check_input_bytes(xml.len())?;
    let mut reader = NsReader::from_str(xml);
    let mut open = Vec::new();
    let mut shape = Shape::default();
    loop {
        match reader.read_event().map_err(reader_err)? {
            Event::Start(element) => {
                let position = shape.observe(&reader, &element, open.last().copied())?;
                open.push(position);
            }
            Event::Empty(element) => {
                shape.observe(&reader, &element, open.last().copied())?;
            }
            Event::End(_) => {
                open.pop();
            }
            Event::DocType(_) => return Err(SamlError::xml("DOCTYPE is not allowed")),
            Event::Eof => break,
            Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::GeneralRef(_) => {}
        }
    }
    let top_level = shape.top_level.ok_or(SamlError::StatusMissing)?;
    Status::received(&top_level, shape.subordinate.as_deref())
}

impl Shape {
    fn observe(
        &mut self,
        reader: &NsReader<&[u8]>,
        element: &BytesStart<'_>,
        parent: Option<Position>,
    ) -> Result<Position, SamlError> {
        let (resolved, local_name) = reader.resolver().resolve_element(element.name());
        let Some(parent) = parent else {
            self.root = local_name.as_ref().to_owned();
            return Ok(Position::Root);
        };
        let is_protocol = |name: &str| -> Result<bool, SamlError> {
            Ok(local_name.as_ref() == name && is_protocol_namespace(&resolved)?)
        };
        match parent {
            Position::Root if is_protocol("Status")? => {
                self.statuses = self.statuses.saturating_add(1);
                at_most_one(self.statuses, &self.root, "Status")?;
                Ok(Position::Status)
            }
            Position::Status if is_protocol("StatusCode")? => {
                self.top_level_codes = self.top_level_codes.saturating_add(1);
                at_most_one(self.top_level_codes, "Status", "StatusCode")?;
                self.top_level = value(element)?;
                Ok(Position::TopLevelCode)
            }
            Position::TopLevelCode if is_protocol("StatusCode")? => {
                self.subordinate_codes = self.subordinate_codes.saturating_add(1);
                at_most_one(self.subordinate_codes, "StatusCode", "StatusCode")?;
                self.subordinate = Some(value(element)?.ok_or_else(|| {
                    SamlError::ProtocolProfile(
                        "subordinate StatusCode is missing required attribute Value".into(),
                    )
                })?);
                Ok(Position::Other)
            }
            Position::Root | Position::Status | Position::TopLevelCode | Position::Other => {
                Ok(Position::Other)
            }
        }
    }
}

fn at_most_one(count: usize, parent: &str, child: &str) -> Result<(), SamlError> {
    if count > 1 {
        return Err(SamlError::ProtocolProfile(format!(
            "{parent} allows at most one {child}"
        )));
    }
    Ok(())
}

fn is_protocol_namespace(resolved: &ResolveResult<'_>) -> Result<bool, SamlError> {
    match resolved {
        ResolveResult::Bound(Namespace(uri)) => {
            Ok(quick_xml::escape::unescape(uri).map_err(xml_err)? == namespace::PROTOCOL)
        }
        ResolveResult::Unbound | ResolveResult::Unknown(_) => Ok(false),
    }
}

fn value(element: &BytesStart<'_>) -> Result<Option<String>, SamlError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_err)?;
        if attribute.key.prefix().is_none() && attribute.key.local_name().as_ref() == "Value" {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(xml_err)?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}
