# Use a non-SAML namespace for AuthnRequest extensions

`ExtensionElement::from_xml` now returns `SamlError::Invalid` for a root
element in any namespace that SAML defines. Before, it refused only no
namespace and the SAML 2.0 protocol, assertion, and metadata namespaces.

The refused namespaces are the target namespaces of the SAML V2.0 schemas
and the SAML V1.x assertion and protocol namespaces. They include
`urn:oasis:names:tc:SAML:2.0:ac`, every
`urn:oasis:names:tc:SAML:2.0:ac:classes:` schema namespace, and
`urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp`. SAML Core §3.2.1 requires
extension elements to use a namespace that SAML does not define. The
namespaces of approved SAML extensions, such as
`urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo`, are still accepted.

This affects a service provider that passes such an element to
`StartSso::extension`. No code fails to compile. Put the element in a
namespace that your deployment owns, and agree on it with the identity
provider.
