use std::time::{Duration as StdDuration, SystemTime};

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::error::{RootValidUntilReason, SamlError, TimeWindowField};
use crate::validator::offset_datetime_from_system_time;
use crate::xml::parse_timezoned_date_time;
use crate::xml::protocol_element::SamlElement;

#[derive(Debug, Clone, Default)]
pub(super) struct ValidUntilBounds {
    root: Option<String>,
    bounds: Vec<String>,
}

impl ValidUntilBounds {
    pub(super) fn from_path(path: &[&SamlElement]) -> Self {
        Self {
            root: path
                .first()
                .and_then(|root| group_valid_until(root))
                .map(str::to_owned),
            bounds: path
                .iter()
                .filter_map(|element| group_valid_until(element))
                .map(str::to_owned)
                .collect(),
        }
    }

    pub(super) fn push_role(&mut self, descriptor: &SamlElement) {
        self.bounds
            .extend(descriptor.attr("validUntil").map(str::to_owned));
    }
}

fn group_valid_until(element: &SamlElement) -> Option<&str> {
    match element.local_name.as_str() {
        "EntitiesDescriptor" | "EntityDescriptor" => element.attr("validUntil"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataValidity {
    valid_until: Option<OffsetDateTime>,
    root: RootValidUntil,
}

impl MetadataValidity {
    pub(super) fn from_bounds(bounds: &ValidUntilBounds) -> Result<Self, SamlError> {
        let mut valid_until: Option<OffsetDateTime> = None;
        for bound in &bounds.bounds {
            let bound = parse_valid_until(bound)?;
            valid_until = Some(valid_until.map_or(bound, |earliest| earliest.min(bound)));
        }
        Ok(Self {
            valid_until,
            root: RootValidUntil::parse(bounds.root.as_deref())?,
        })
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

    pub(crate) fn root(self) -> RootValidUntil {
        self.root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootValidUntil(Option<OffsetDateTime>);

impl RootValidUntil {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, SamlError> {
        value.map(parse_valid_until).transpose().map(Self)
    }

    pub(crate) fn ensure_within(
        self,
        now: SystemTime,
        max_validity: StdDuration,
    ) -> Result<(), SamlError> {
        let Some(valid_until) = self.0 else {
            return Err(root_valid_until_refused(RootValidUntilReason::Missing));
        };
        if valid_until - offset_datetime_from_system_time(now)? > max_validity {
            return Err(root_valid_until_refused(
                RootValidUntilReason::BeyondMaxValidity,
            ));
        }
        Ok(())
    }
}

fn root_valid_until_refused(reason: RootValidUntilReason) -> SamlError {
    SamlError::MetadataRootValidUntilRefused { reason }
}

fn parse_valid_until(value: &str) -> Result<OffsetDateTime, SamlError> {
    let normalized = parse_timezoned_date_time(value).ok_or_else(metadata_valid_until)?;
    let Some((date, rest)) = normalized.split_once("T24:") else {
        return OffsetDateTime::parse(normalized, &Rfc3339).map_err(|_| metadata_valid_until());
    };

    let midnight = OffsetDateTime::parse(&format!("{date}T00:{rest}"), &Rfc3339)
        .map_err(|_| metadata_valid_until())?;
    midnight
        .checked_add(Duration::days(1))
        .filter(|next_day| next_day.year() <= 9999)
        .ok_or_else(metadata_valid_until)
}

fn metadata_valid_until() -> SamlError {
    SamlError::TimeWindowInvalid {
        field: TimeWindowField::MetadataValidUntil,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use crate::error::{RootValidUntilReason, SamlError, TimeWindowField};
    use crate::metadata::{IdpMetadata, SpMetadata};
    use crate::{EntityId, IdpDescriptor, MetadataTrustPolicy, SpDescriptor};

    const Y2030: u64 = 1_893_456_000;
    const MAX_VALIDITY: Duration = Duration::from_secs(28 * 86_400);

    fn at(unix_seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds)
    }

    fn is_valid_until_error(result: &Result<(), SamlError>) -> bool {
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

    fn idp_descriptor(xml: &str) -> Result<IdpDescriptor, SamlError> {
        IdpDescriptor::from_metadata_xml(
            EntityId::try_new("https://idp.example.com/metadata")?,
            xml,
            MetadataTrustPolicy::Unverified,
        )
    }

    fn root_refused(result: Result<IdpDescriptor, SamlError>) -> Option<RootValidUntilReason> {
        match result {
            Err(SamlError::MetadataRootValidUntilRefused { reason }) => Some(reason),
            _ => None,
        }
    }

    #[test]
    fn a_root_valid_until_is_accepted_up_to_the_max_validity() -> Result<(), SamlError> {
        let earliest_accepted = at(Y2030) - MAX_VALIDITY;
        for xml in [
            entity(&valid_until("2030-01-01T00:00:00Z"), "", ""),
            format!(
                r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"{}>{}</EntitiesDescriptor>"#,
                valid_until("2030-01-01T00:00:00Z"),
                entity("", "", "")
            ),
        ] {
            idp_descriptor(&xml)?.require_root_valid_until(earliest_accepted, MAX_VALIDITY)?;
            assert_eq!(
                root_refused(idp_descriptor(&xml)?.require_root_valid_until(
                    earliest_accepted - Duration::from_secs(1),
                    MAX_VALIDITY
                )),
                Some(RootValidUntilReason::BeyondMaxValidity),
                "{xml}"
            );

            let expired =
                idp_descriptor(&xml)?.require_root_valid_until(at(Y2030), MAX_VALIDITY)?;
            assert!(
                is_valid_until_error(&expired.ensure_valid_at(at(Y2030))),
                "{xml}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_valid_until_below_the_root_does_not_satisfy_the_root_requirement() -> Result<(), SamlError>
    {
        let near = valid_until("2030-01-01T00:00:00Z");
        let now = at(Y2030 - 86_400);
        for xml in [
            entity("", "", ""),
            entity("", &near, ""),
            format!(
                r#"<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">{}</EntitiesDescriptor>"#,
                entity(&near, &near, "")
            ),
        ] {
            assert_eq!(
                root_refused(idp_descriptor(&xml)?.require_root_valid_until(now, MAX_VALIDITY)),
                Some(RootValidUntilReason::Missing),
                "{xml}"
            );
        }

        let sp = SpDescriptor::from_metadata_xml(
            EntityId::try_new("https://idp.example.com/metadata")?,
            &entity("", "", &near),
            MetadataTrustPolicy::Unverified,
        )?;
        assert!(matches!(
            sp.require_root_valid_until(now, MAX_VALIDITY),
            Err(SamlError::MetadataRootValidUntilRefused {
                reason: RootValidUntilReason::Missing
            })
        ));
        Ok(())
    }

    #[test]
    fn metadata_is_invalid_from_valid_until_onward() -> Result<(), SamlError> {
        for (value, expires_at) in [
            ("2030-01-01T00:00:00Z", Y2030),
            ("2029-12-31T24:00:00Z", Y2030),
            ("2029-12-31T24:00:00.000-02:00", Y2030 + 7_200),
        ] {
            let xml = entity(&valid_until(value), "", "");
            let descriptor = IdpDescriptor::from_metadata_xml(
                EntityId::try_new("https://idp.example.com/metadata")?,
                &xml,
                MetadataTrustPolicy::Unverified,
            )?;

            descriptor.ensure_valid_at(at(expires_at - 1))?;
            assert!(
                is_valid_until_error(&descriptor.ensure_valid_at(at(expires_at))),
                "{value}"
            );
            assert!(
                is_valid_until_error(&descriptor.ensure_valid_at(at(expires_at + 1))),
                "{value}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_timezone_offset_names_the_same_instant() -> Result<(), SamlError> {
        let xml = entity(&valid_until("2030-01-01T02:00:00+02:00"), "", "");
        let validity = IdpMetadata::from_xml(&xml)?.as_metadata().validity()?;

        validity.ensure_valid_at(at(Y2030 - 1))?;
        assert!(is_valid_until_error(&validity.ensure_valid_at(at(Y2030))));
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
            let validity = IdpMetadata::from_xml(&xml)?.as_metadata().validity()?;
            validity.ensure_valid_at(at(Y2030 - 1))?;
            assert!(
                is_valid_until_error(&validity.ensure_valid_at(at(Y2030))),
                "{xml}"
            );
        }
        Ok(())
    }

    #[test]
    fn another_role_descriptor_does_not_bound_this_role() -> Result<(), SamlError> {
        let xml = entity("", "", &valid_until("2001-01-01T00:00:00Z"));

        IdpMetadata::from_xml(&xml)?
            .as_metadata()
            .validity()?
            .ensure_valid_at(at(Y2030))?;
        assert!(is_valid_until_error(
            &SpMetadata::from_xml(&xml)?
                .as_metadata()
                .validity()?
                .ensure_valid_at(at(Y2030))
        ));
        Ok(())
    }

    #[test]
    fn cache_duration_does_not_expire_metadata() -> Result<(), SamlError> {
        let xml = entity(r#" cacheDuration="PT1S""#, "", "");

        IdpMetadata::from_xml(&xml)?
            .as_metadata()
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
            "2099-12-31T24:00:00.0000000001Z",
            "9999-12-31T24:00:00+14:00",
            "2099-06-30T12:00:60Z",
            "10000-01-01T00:00:00Z",
            "-0001-01-01T00:00:00Z",
        ] {
            let xml = entity("", &valid_until(value), "");
            assert!(
                matches!(
                    IdpMetadata::from_xml(&xml)?.as_metadata().validity(),
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
