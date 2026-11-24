# Supply the collapsed metadata entity ID

`IdpDescriptor::from_metadata_xml` and `SpDescriptor::from_metadata_xml`
compare the expected ID with the unqualified `entityID` on the metadata
`EntityDescriptor`, after XML Schema whitespace collapse. The same rule
applies to the variants that take `XmlPolicy`.

If you copied an ID with spaces around it from metadata, remove those spaces
from the configured value. For example, pass
`EntityId::try_new("https://idp.example.com/metadata")` when the XML contains
`entityID=" https://idp.example.com/metadata "`. If the ID contains an internal
run of XML whitespace, use one space for that run. If your metadata uses a
prefixed `entityID`, ask the publisher to supply the unqualified attribute.

`IdpMetadata::as_metadata` and `SpMetadata::as_metadata` also return the
collapsed ID through `Metadata::entity_id`. To inspect the original attribute,
use `Metadata::metadata_xml` to read the source document.
