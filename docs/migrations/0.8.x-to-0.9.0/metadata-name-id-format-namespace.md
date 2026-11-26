# Read metadata name identifier formats only in the metadata namespace

This change affects code that reads peer formats with
`Metadata::name_id_formats`, `SpDescriptor::name_id_formats`, or
`IdpDescriptor::name_id_formats`, and flows that pick a format from peer
metadata. No code fails to compile.

saml-rs now reads a `NameIDFormat` only when the element is a child of a
selected role descriptor and is in the SAML metadata namespace,
`urn:oasis:names:tc:SAML:2.0:metadata`. Before, an element with the same local
name in another namespace was read as a format. For example,
`ext:NameIDFormat` in an `md:SPSSODescriptor` appeared in the list and could
become the format an identity provider issues.

The list does not change for a peer that publishes its formats in the metadata
namespace. If a peer publishes a format only in another namespace, the list no
longer contains it. Ask the peer to publish the format as `md:NameIDFormat`.
