use crate::constants::{namespace, CertUse};
use crate::xml::protocol_element::SamlElement;

#[derive(Debug, Clone, Default)]
pub(super) struct KeyCertificates {
    signing: Vec<String>,
    encryption: Vec<String>,
    #[cfg(crypto)]
    role_encryption_keys: Vec<Vec<Vec<String>>>,
}

impl KeyCertificates {
    pub(super) fn from_descriptors(descriptors: &[&SamlElement]) -> Self {
        let mut certificates = Self::default();
        for key_descriptor in descriptors.iter().flat_map(|role| key_descriptors(role)) {
            let x509_certificates: Vec<String> = key_infos(key_descriptor)
                .flat_map(x509_data)
                .flat_map(x509_certificates)
                .map(|certificate| certificate.text.clone())
                .collect();
            match key_use(key_descriptor) {
                None => {
                    certificates
                        .signing
                        .extend(x509_certificates.iter().cloned());
                    certificates.encryption.extend(x509_certificates);
                }
                Some(use_) if use_ == CertUse::Signing.as_str() => {
                    certificates.signing.extend(x509_certificates);
                }
                Some(use_) if use_ == CertUse::Encryption.as_str() => {
                    certificates.encryption.extend(x509_certificates);
                }
                Some(_) => {}
            }
        }
        #[cfg(crypto)]
        {
            certificates.role_encryption_keys = descriptors
                .iter()
                .map(|role| encryption_x509_data(role))
                .collect();
        }
        certificates
    }

    #[cfg(crypto)]
    pub(super) fn role_encryption_keys(&self, role: usize) -> &[Vec<String>] {
        self.role_encryption_keys
            .get(role)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn for_use(&self, use_: CertUse) -> &[String] {
        match use_ {
            CertUse::Signing => &self.signing,
            CertUse::Encryption => &self.encryption,
        }
    }
}

fn key_descriptors(role: &SamlElement) -> impl Iterator<Item = &SamlElement> {
    role.children
        .iter()
        .filter(|child| child.is(namespace::METADATA, "KeyDescriptor"))
}

fn key_use(key_descriptor: &SamlElement) -> Option<&str> {
    key_descriptor
        .attrs
        .iter()
        .find(|(_, name, _)| name == "use")
        .map(|(_, _, value)| value.as_str())
}

fn key_infos(key_descriptor: &SamlElement) -> impl Iterator<Item = &SamlElement> {
    key_descriptor
        .children
        .iter()
        .filter(|child| child.is(namespace::DSIG, "KeyInfo"))
}

fn x509_data(key_info: &SamlElement) -> impl Iterator<Item = &SamlElement> {
    key_info
        .children
        .iter()
        .filter(|child| child.is(namespace::DSIG, "X509Data"))
}

fn x509_certificates(x509_data: &SamlElement) -> impl Iterator<Item = &SamlElement> {
    x509_data
        .children
        .iter()
        .filter(|child| child.is(namespace::DSIG, "X509Certificate"))
}

#[cfg(crypto)]
fn encryption_x509_data(role: &SamlElement) -> Vec<Vec<String>> {
    key_descriptors(role)
        .filter(|key_descriptor| {
            key_use(key_descriptor).is_none_or(|use_| use_ == CertUse::Encryption.as_str())
        })
        .flat_map(key_infos)
        .flat_map(x509_data)
        .map(|x509_data| {
            x509_certificates(x509_data)
                .map(|certificate| certificate.text.clone())
                .collect::<Vec<_>>()
        })
        .filter(|certificates| !certificates.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::constants::CertUse;
    use crate::error::SamlError;
    use crate::metadata::{Metadata, SpMetadata};

    #[test]
    fn reads_key_descriptor_certificates_only_in_the_xml_signature_namespace(
    ) -> Result<(), SamlError> {
        const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
        const OTHER: &str = "urn:example:other";
        let certificate = "MIIBkey";
        let key_descriptor = |key_descriptor: &str, key_info: &str, x509_data: &str, x509: &str| {
            format!(
                r#"<{key_descriptor} xmlns:ds="{DS}" xmlns:o="{OTHER}"><{key_info}><{x509_data}><{x509}>{certificate}</{x509}></{x509_data}></{key_info}></{key_descriptor}>"#
            )
        };
        let read = key_descriptor(
            "KeyDescriptor",
            "ds:KeyInfo",
            "ds:X509Data",
            "ds:X509Certificate",
        );
        let ignored = [
            key_descriptor(
                "o:KeyDescriptor",
                "ds:KeyInfo",
                "ds:X509Data",
                "ds:X509Certificate",
            ),
            key_descriptor(
                "KeyDescriptor",
                "KeyInfo",
                "ds:X509Data",
                "ds:X509Certificate",
            ),
            key_descriptor(
                "KeyDescriptor",
                "ds:KeyInfo",
                "o:X509Data",
                "ds:X509Certificate",
            ),
            key_descriptor(
                "KeyDescriptor",
                "ds:KeyInfo",
                "ds:X509Data",
                "o:X509Certificate",
            ),
        ];
        let metadata = |key_descriptor: &str| {
            format!(
                r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key_descriptor}<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
            )
        };
        let certificates = |xml: &str| -> Result<Vec<Vec<String>>, SamlError> {
            let typed = SpMetadata::from_xml(xml)?;
            let any_role = Metadata::parse(xml)?;
            Ok([typed.as_metadata(), &any_role]
                .iter()
                .flat_map(|metadata| {
                    [
                        metadata.x509_certificates(CertUse::Signing).to_vec(),
                        metadata.x509_certificates(CertUse::Encryption).to_vec(),
                        #[cfg(crypto)]
                        metadata.role_encryption_key_certificates(0).concat(),
                    ]
                })
                .collect())
        };
        for certificates in certificates(&metadata(&read))? {
            assert_eq!(certificates, [certificate]);
        }
        let qualified_use = format!(
            r#"<KeyDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" md:use="encryption"><ds:KeyInfo xmlns:ds="{DS}"><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"#
        );
        let typed = SpMetadata::from_xml(&metadata(&qualified_use))?;
        assert!(typed
            .as_metadata()
            .x509_certificates(CertUse::Signing)
            .is_empty());
        assert_eq!(
            typed.as_metadata().x509_certificates(CertUse::Encryption),
            [certificate]
        );
        for key_descriptor in ignored {
            for certificates in certificates(&metadata(&key_descriptor))? {
                assert!(certificates.is_empty(), "{key_descriptor}");
            }
        }
        Ok(())
    }
}
