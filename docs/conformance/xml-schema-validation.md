# XML schema validation

`XmlPolicy::schema_validator` is an optional application callback, not an XSD
engine, and it claims no conformance with a SAML profile. The typed operations
of the identity provider and the service provider pass it the XML they receive
on every binding, and an explicit metadata import passes it the metadata.

Normative text is Core §1.1, under which the schema documents and the
normative text define the syntax, and Core §1.3, which defines string, time,
and identifier values. No OASIS document defines this callback. Core §3.2.1
lets a responder decide that a request is invalid and requires the `Requester`
status only when it answers, and no OASIS rule tells a receiver to reject every
schema-invalid message.

## Library policies

### Receiver: `XmlPolicy::schema_validator`

Code: `src/schema.rs`, `src/flow.rs`, `src/encrypted_elements.rs`, `src/logout/encrypted_id.rs`, `src/api/requested_subject.rs`, `src/browser/input.rs`, `src/soap.rs`, `src/artifact.rs`, `src/name_id_management.rs`, `src/name_id_management/encryption.rs`, `src/metadata/read.rs`

The callback receives a document only after the parser accepts it: within the
[XML input limits](xml-input.md#resource-limits), and without a
[document type declaration](xml-input.md#document-type-declarations).

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Pass each received protocol document, SOAP envelope, and decrypted protocol document to the callback. Do not pass XML the crate generates, or a reparse of a document already passed | The application owns its schema set, so its validator can refuse input that no OASIS receiver rule refuses. | Core §1.1 | `XmlPolicy::schema_validator` |
| Pass the original metadata document to the callback only when the import takes an `XmlPolicy` | Metadata is imported before the role configuration exists. | Core §1.1 | `XmlPolicy::schema_validator` on `IdpDescriptor::from_metadata_xml_with_xml_policy`, `SpDescriptor::from_metadata_xml_with_xml_policy`, `metadata::IdpMetadata::from_xml_with_policy`, `metadata::SpMetadata::from_xml_with_policy`, and `metadata::Metadata::parse_with_policy` |
| Keep every built-in check that applies when the callback accepts the document | A schema-valid document can still fail its signature, trust, correlation, audience, time, or replay check. | — | Always |

A validator supports the schemas of every input that the configured role
reads. It keeps the lax processing of the Core §7.2 wildcard extension points,
so an extension element that its schema set does not declare is not an error
there.

<a id="baseline-receipt"></a>

### Receiver: typed receive operations

Code: `src/model/identifiers.rs`, `src/config/descriptors.rs`, `src/name_id_management.rs`, `src/model/authn.rs`, `src/model/extract.rs`, `src/assertion_acceptance.rs`, `src/xml/protocol_element.rs`, `src/xml/schema_value.rs`, `src/xml/date_time.rs`, `src/xml/profile.rs`, `src/xml/extract.rs`, `src/xml/dom.rs`

Without a `SchemaValidator`, the typed receive operations check the schema
rules of the values they read and return. They do not validate the rest of a
message against the SAML schemas.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Read a returned request, response, or assertion `ID`, and a returned `InResponseTo`, as a string with a character other than XML whitespace, without the `xs:ID` or `NCName` check. Collapse XML whitespace in an `AuthnRequest` `ID` and in a returned `InResponseTo` | Peers that write an `ID` that is not an `NCName`, such as a UUID that starts with a digit, keep working, as they do with most compared SAML implementations. | Core §1.3.4, `RequestAbstractType`, `StatusResponseType`, `AssertionType` | Always |
| Treat an entity ID, a message or assertion `ID`, a `SessionIndex`, or an instant as empty only when it holds nothing but XML whitespace: space, tab, carriage return, and line feed. Another character, such as U+00A0, is content | Core §1.3.1 counts only XML whitespace as whitespace, so treating another character as empty would refuse a valid SAML string. | Core §1.3.1, XML 1.0 §2.3 | Always |
| Accept a name identifier management `Terminate` that holds only XML whitespace, and refuse one that holds another character, such as U+00A0 | Reason not recorded. | `TerminateType`, XML Schema Part 1 §3.4.4 | Always |
| Read each returned `xs:boolean`, `xs:unsignedShort`, and `xs:dateTime` attribute by its datatype, and reject a value outside its lexical space | A typed result cannot hold a value that its datatype does not define, so the alternatives are to guess the value or to drop it. | Core §3.2.1, protocol and assertion schemas | Always |
| Return an `AttributeValue` as text whatever its `xsi:type` | Reason not recorded. | `AttributeType`, Core §2.7.3.1.1 | Always |
| Read a protocol message `IssueInstant` only in the UTC form that ends in `Z` | Core §1.3.3 makes another form an invalid SAML time value, and accepting an offset would convert a value that its sender had to write in UTC. | Core §1.3.3 | Always |
| Ignore an undeclared unqualified attribute, a child element in a position the reader does not read or inside a text-only element such as `NameID`, sibling order, text between children, and an empty `Extensions`, unless the flow record rejects it. Read a text-only element as its direct text. [SSO acceptance](web-browser-sso-acceptance.md#service-provider) rejects an undeclared `Conditions` attribute and a child element in a text-only value of the service provider's selected assertion | Values are read by expanded name, so ignored content changes no returned value. | Core §3.2.1, §7.2 | `XmlPolicy::schema_validator` |
| In SSO receipt, once the identity provider is known, accept a second `Issuer` or a second `Subject` in an assertion other than the selected one, and compare only its first `Issuer`. [SSO acceptance](web-browser-sso-acceptance.md#service-provider) rejects both in the selected assertion, and a second `Issuer` in an assertion used for IdP lookup | Profiles §4.1.4.3 discards an invalid assertion without refusing the response, and the session reads no value from that assertion. | `AssertionType`, Profiles §4.1.4.2, §4.1.4.3, E26 | Always |

A flow record can add a stricter rule. The
[SSO acceptance](web-browser-sso-acceptance.md) record states the rules for an
assertion the service provider relies on.

### Producer and receiver: name datatype checks

Code: `src/xml/name.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Check an `xs:Name`, `xs:NCName`, or `xs:ID` value, such as a basic attribute name or a written `InResponseTo`, against the XML 1.0 Fifth Edition name characters | The older table that XML Schema 1.0 cites rejects names that current XML accepts, such as one starting with U+037F, and generated IDs are ASCII. | XML 1.0 §2.3, XML Schema Part 2 §3.3.6, §3.3.7, §3.3.8 | Always |
