# Handle status shape errors and SOAP replies

## Expect an error for a response with more than one status

The protocol schema gives a SAML response exactly one `Status`. That
`Status` holds exactly one top-level `StatusCode`. A `StatusCode` holds at
most one subordinate `StatusCode`, and every `StatusCode` carries `Value`.
The protocol schema also allows at most one `Issuer` on a response.

saml-rs now enforces that shape when it reads the status of a received
`Response`, `LogoutResponse`, `ManageNameIDResponse`, or `ArtifactResponse`.
Before, saml-rs read the first matching `StatusCode` and ignored the others. `ArtifactResolution::finish` read the first `Issuer`.

A response that breaks the shape now returns `SamlError::ProtocolProfile`
from `ServiceProvider::finish_sso`, `accept_unsolicited_sso`, `finish_slo`
on both roles, `finish_name_id_management_redirect` on both roles,
`StartedNameIdManagement::finish`, and `ArtifactResolution::finish`. A
missing `Status`, `StatusCode`, or top-level `Value` still returns
`SamlError::StatusMissing`.

You do not need to change code. If a peer sends its subordinate code next to
the top-level code instead of inside it, ask the peer to nest it:

```xml
<samlp:Status>
	<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/>
	</samlp:StatusCode>
</samlp:Status>
```
