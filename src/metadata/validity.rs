//! Effective `validUntil` of imported metadata.

use std::time::SystemTime;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{SamlError, TimeWindowField};
use crate::validator::offset_datetime_from_system_time;
use crate::xml::{dom, parse_timezoned_date_time};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataValidity {
    valid_until: Option<OffsetDateTime>,
}

impl MetadataValidity {
    pub(super) fn from_bounds(bounds: &[String]) -> Result<Self, SamlError> {
        let mut valid_until: Option<OffsetDateTime> = None;
        for bound in bounds {
            let bound = parse_valid_until(bound)?;
            valid_until = Some(valid_until.map_or(bound, |earliest| earliest.min(bound)));
        }
        Ok(Self { valid_until })
    }

    pub(crate) fn ensure_valid_at(self, now: SystemTime) -> Result<(), SamlError> {
        let Some(valid_until) = self.valid_until else {
            return Ok(());
        };
        if offset_datetime_from_system_time(now)? >= valid_until {
            return Err(metadata_valid_until());
        }
        Ok(())
    }
}

fn parse_valid_until(value: &str) -> Result<OffsetDateTime, SamlError> {
    let normalized = parse_timezoned_date_time(value).ok_or_else(metadata_valid_until)?;
    OffsetDateTime::parse(normalized, &Rfc3339).map_err(|_| metadata_valid_until())
}

fn metadata_valid_until() -> SamlError {
    SamlError::TimeWindowInvalid {
        field: TimeWindowField::MetadataValidUntil,
    }
}

pub(super) fn valid_until_bounds(roots: &[dom::Node], descriptors: &[&dom::Node]) -> Vec<String> {
    roots
        .iter()
        .find_map(|root| entity_bounds(root, descriptors))
        .unwrap_or_default()
}

fn entity_bounds(node: &dom::Node, descriptors: &[&dom::Node]) -> Option<Vec<String>> {
    let mut bounds: Vec<String> = if node.local_name == "EntityDescriptor" {
        descriptors
            .iter()
            .filter_map(|descriptor| descriptor.attr("validUntil"))
            .map(str::to_string)
            .collect()
    } else {
        node.children
            .iter()
            .find_map(|child| entity_bounds(child, descriptors))?
    };
    if matches!(
        node.local_name.as_str(),
        "EntityDescriptor" | "EntitiesDescriptor"
    ) {
        bounds.extend(node.attr("validUntil").map(str::to_string));
    }
    Some(bounds)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use crate::error::{SamlError, TimeWindowField};
    use crate::metadata::{IdpMetadata, SpMetadata};

    const Y2030: u64 = 1_893_456_000;

    fn at(unix_seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds)
    }

    fn is_valid_until_error(result: Result<(), SamlError>) -> bool {
        matches!(
            result,
            Err(SamlError::TimeWindowInvalid {
                field: TimeWindowField::MetadataValidUntil
            })
        )
    }

    fn entity(entity_valid_until: &str, idp_valid_until: &str, sp_valid_until: &str) -> String {
        format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"{entity_valid_until}><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"{idp_valid_until}><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"{sp_valid_until}><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
        )
    }

    fn valid_until(value: &str) -> String {
        format!(r#" validUntil="{value}""#)
    }

    #[test]
    fn metadata_is_invalid_from_valid_until_onward() -> Result<(), SamlError> {
        let xml = entity(&valid_until("2030-01-01T00:00:00Z"), "", "");
        let validity = IdpMetadata::from_xml(&xml)?.validity()?;

        validity.ensure_valid_at(at(Y2030 - 1))?;
        assert!(is_valid_until_error(validity.ensure_valid_at(at(Y2030))));
        assert!(is_valid_until_error(
            validity.ensure_valid_at(at(Y2030 + 1))
        ));
        Ok(())
    }

    #[test]
    fn a_timezone_offset_names_the_same_instant() -> Result<(), SamlError> {
        let xml = entity(&valid_until("2030-01-01T02:00:00+02:00"), "", "");
        let validity = IdpMetadata::from_xml(&xml)?.validity()?;

        validity.ensure_valid_at(at(Y2030 - 1))?;
        assert!(is_valid_until_error(validity.ensure_valid_at(at(Y2030))));
        Ok(())
    }

    #[test]
    fn the_earliest_of_parent_entity_and_role_takes_precedence() -> Result<(), SamlError> {
        let later = valid_until("2031-01-01T00:00:00Z");
        let earliest = valid_until("2030-01-01T00:00:00Z");
        let documents = [
            format!(
                r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"{earliest}>{}</EntitiesDescriptor>"#,
                entity(&later, &later, "")
            ),
            format!(
                r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"{earliest}><EntitiesDescriptor{later}>{}</EntitiesDescriptor></EntitiesDescriptor>"#,
                entity(&later, &later, "")
            ),
            entity(&earliest, &later, ""),
            entity(&later, &earliest, ""),
        ];

        for xml in documents {
            let validity = IdpMetadata::from_xml(&xml)?.validity()?;
            validity.ensure_valid_at(at(Y2030 - 1))?;
            assert!(
                is_valid_until_error(validity.ensure_valid_at(at(Y2030))),
                "{xml}"
            );
        }
        Ok(())
    }

    #[test]
    fn another_role_descriptor_does_not_bound_this_role() -> Result<(), SamlError> {
        let xml = entity("", "", &valid_until("2001-01-01T00:00:00Z"));

        IdpMetadata::from_xml(&xml)?
            .validity()?
            .ensure_valid_at(at(Y2030))?;
        assert!(is_valid_until_error(
            SpMetadata::from_xml(&xml)?
                .validity()?
                .ensure_valid_at(at(Y2030))
        ));
        Ok(())
    }

    #[test]
    fn cache_duration_does_not_expire_metadata() -> Result<(), SamlError> {
        let xml = entity(r#" cacheDuration="PT1S""#, "", "");

        IdpMetadata::from_xml(&xml)?
            .validity()?
            .ensure_valid_at(at(Y2030))
    }

    #[test]
    fn a_malformed_or_local_valid_until_is_rejected() -> Result<(), SamlError> {
        for value in [
            "2030-01-01T00:00:00",
            "2030-01-01",
            "2030-01-01T00:00:00+15:00",
            "soon",
            "2099-12-31T24:00:00Z",
            "2099-06-30T12:00:60Z",
            "10000-01-01T00:00:00Z",
            "-0001-01-01T00:00:00Z",
        ] {
            let xml = entity("", &valid_until(value), "");
            assert!(
                matches!(
                    IdpMetadata::from_xml(&xml)?.validity(),
                    Err(SamlError::TimeWindowInvalid {
                        field: TimeWindowField::MetadataValidUntil
                    })
                ),
                "{value}"
            );
        }
        Ok(())
    }
}
