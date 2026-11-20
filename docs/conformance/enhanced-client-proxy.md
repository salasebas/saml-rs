# Enhanced Client/Proxy SSO over PAOS

Typed service-provider and identity-provider ends of one Enhanced Client/Proxy
login. The source is Profiles §4.2 and Bindings §3.3 (`saml-profiles-2.0-os`
and `saml-bindings-2.0-os`, 15 March 2005), as corrected by Approved Errata 05
E20, E22, and E54. The browser SSO rules that §4.2 incorporates are the rows
in [generation](web-browser-sso-generation.md) and
[acceptance](web-browser-sso-acceptance.md).

This page does not claim the IdP operational mode or the SP operational mode.
The ECP column of Conformance Requirements Table 2 is a separate role and has
no facade here. IdP, IdP Lite, SP, and SP Lite share this Table 2 cell, so
one exchange covers all four columns.

The service provider calls `start_paos_sso`, then `finish_paos_sso` or
`finish_paos_sso_with_outstanding_logout`. It may call
`check_paos_client_headers` first to decide whether the HTTP client is an
enhanced client. The identity provider calls `receive_paos_sso`, then
`respond_paos_sso` with `RespondPaosSso::success` or `RespondPaosSso::failure`.
`StartSso` and `RespondSso` are unchanged.

## Service provider

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Accept the exchange when `Accept` lists `application/vnd.paos+xml` and the PAOS header carries `ver="urn:liberty:paos:2003-08"` and `"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"` | Service provider | Read the enhanced client's HTTP request | Mandatory for the sender, the enhanced client. Bindings §3.3.3, Profiles §4.2.3.1, Errata 05 E54. The service provider's check is optional: `check_paos_client_headers` performs it, and `start_paos_sso` does not read HTTP headers. `check_paos_client_headers` rejects a header that uses the single quotes E54 removed. That rejection is library policy. E54 replaced those quotes because they are problematic, and the corrected header value uses double quotes, so a single-quoted header is not that value |
| HTTP 200 whose body is one SOAP envelope | Service provider | Send the AuthnRequest | Mandatory. Profiles §4.2.3.2. The body contains one AuthnRequest, a `paos:Request`, and an `ecp:Request` |
| `paos:Request` `responseConsumerURL` is the assertion consumer URL on the AuthnRequest | Service provider | Send the AuthnRequest | Mandatory. Profiles §4.2.4.1, with E22's attribute name. The URL is the service provider's default assertion consumer, or `StartPaosSso::acs_url` when that URL is already published. Only HTTP-POST and HTTP-POST-SimpleSign endpoints are considered. `ProtocolBinding` is omitted. The return path is this profile |
| `paos:Request` `service` is `urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp`, `mustUnderstand` is `1`, and `actor` is `http://schemas.xmlsoap.org/soap/actor/next` | Service provider | Send the AuthnRequest | Mandatory. Profiles §4.2.4.1. `messageID` is omitted, so the enhanced client is not required to return `paos:Response` |
| `ecp:Request` carries the service provider's entity identifier, with `Format` omitted | Service provider | Send the AuthnRequest | Mandatory. Profiles §4.2.4.2. `IDPList` names the identity provider passed to `start_paos_sso` and its SOAP endpoint. That list is optional in the profile. `IsPassive` is `false` unless `StartPaosSso::passive` says otherwise, because an omitted value means passive |
| `ecp:Request` `ProviderName` is written when set, with any XML 1.0 characters, including none | Service provider | Send the AuthnRequest | Optional. Profiles §4.2.4.2 and the ECP schema `RequestType` make `ProviderName` an optional `xs:string`. `StartPaosSso::provider_name` sets it, and an empty name is sent. A character XML 1.0 forbids cannot be written, so `start_paos_sso` returns `SamlError::Invalid` for it. `start_sso` applies the same rule to the AuthnRequest `ProviderName` |
| `ecp:RelayState`, when sent, is at most 80 bytes | Service provider | Send the AuthnRequest | Mandatory prohibition. Profiles §4.2.4.3. `start_paos_sso` refuses a longer value |
| Sign the AuthnRequest | Service provider | Send the AuthnRequest | Recommendation. Profiles §4.2.5. Signing is on unless `StartPaosSso::allow_unsigned_authn_request`. The signature is the enveloped HTTP-POST signature |
| Cache-Control `no-cache, no-store, must-revalidate, private` and Pragma `no-cache` | Service provider | HTTP response | Recommendation. Bindings §3.3.4. Always included on `PaosHttpResponse` |
| Content-Type `application/vnd.paos+xml` | Service provider | HTTP response | The media type Bindings §3.3.3 requires the client to accept |
| Consume the SOAP response with the HTTP-POST Web SSO rules | Service provider | Receive the response | Mandatory. Profiles §4.2.3.8, which applies §§4.1.4.3 and 4.1.4.5. `finish_paos_sso` checks the pending request ID, issuer, assertion consumer, and signatures through that path |
| When the service provider sent `ecp:RelayState`, the returned header matches it | Service provider | Receive the response | The profile requires the enhanced client to return that value. A mismatch fails the login. When the service provider sent none, a later header does not fail the login, because the identity provider may supply one, and `SsoSession::relay_state` reports it. The header is the ECP `RelayState` element, and its namespace declaration may sit on an ancestor |
| A SOAP header entry with `mustUnderstand` `1` or `true` is refused, except `ecp:RelayState` and `paos:Response` | Service provider | Receive the response | Mandatory. SOAP 1.1 §4.2.3, for the SOAP receiver of the PAOS response, Bindings §3.3: the recipient of such an entry obeys it or fails the message. The service provider processes `ecp:RelayState`, whose `mustUnderstand` Profiles §4.2.4.3 fixes at `1`, and `paos:Response`, Profiles §4.2.4.5. `paos:Request` carries no `messageID`, so `paos:Response` has no message to correlate. `finish_paos_sso` returns `SamlError::Xml`. The rule ignores SOAP `actor`, so an entry aimed at another actor is refused too. An unprefixed `mustUnderstand`, and the value `true`, which §4.2.3 does not define, are refused the same way. These refusals are library policy beyond SOAP 1.1 §§4.2.2 and 4.2.3, as on the [artifact resolution](artifact-resolution.md) SOAP reader: an entry that reaches this endpoint was not processed by the actor it names |
| An `ecp:RelayState` longer than 80 bytes is rejected | Service provider | Receive the response | Library policy. Profiles §4.2.4.3 forbids the requester from exceeding 80 bytes, and the returned value has to be identical to that header. A longer value cannot be the header the profile allows, and the service provider stores relay state with the same limit |
| An assertion that matches an outstanding logout is rejected | Service provider | Receive the response | The same rule as typed `finish_sso_with_outstanding_logout`, through `finish_paos_sso_with_outstanding_logout` |
| A SAML error status does not establish a session | Service provider | Receive the response | Mandatory for the success path. Profiles §4.1.4.2, incorporated by §4.2.3.6: an error response contains no assertions. `finish_paos_sso` returns `StatusNotSuccess` |

## Identity provider

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Read one AuthnRequest from the SOAP body and do not require SOAP headers | Identity provider | Receive the AuthnRequest | Mandatory. Bindings §3.2.2. `Envelope`, `Header`, and `Body` are the SOAP 1.1 elements. The identity provider does not read `SOAPAction` |
| A SOAP header entry with `mustUnderstand` `1` or `true` is refused | Identity provider | Receive the AuthnRequest | Mandatory. SOAP 1.1 §4.2.3, for the SOAP receiver of the AuthnRequest, Bindings §3.2 and Profiles §4.2.3.4: the recipient of such an entry obeys it or fails the message. The identity provider processes no header entry. `receive_paos_sso` returns `SamlError::Xml`. `PaosHttpResponse::soap_fault` answers it with a `Client` fault. The SOAP 1.1 §4.4.1 `MustUnderstand` fault code is not generated, and this row does not claim it. SOAP `actor`, an unprefixed `mustUnderstand`, and the value `true` follow the service provider row, as library policy |
| `Destination`, when present, is the SOAP endpoint that received the POST | Identity provider | Receive the AuthnRequest | Mandatory when present. Core §3.2.1, against the `soap_endpoint` passed to `receive_paos_sso`. A missing `Destination` is accepted under every `AuthnRequestValidationPolicy`, signed or not. The SOAP and PAOS bindings do not require `Destination` on a signed message, unlike Bindings §§3.4.5.2 and 3.5.5.2. Under Profiles §4.2.3.3 the enhanced client chooses the identity provider, so the service provider may not know the endpoint. Single Logout over SOAP follows the same rule |
| A `ProtocolBinding` that names `urn:oasis:names:tc:SAML:2.0:bindings:PAOS` is accepted | Identity provider | Receive the AuthnRequest | Core §3.4.1 lets the requester name the response binding, and Bindings §3.3.1 identifies this one. `AuthnRequest::protocol_binding` reports none for it. Any other binding follows the typed `receive_sso` rule |
| SOAP fault when the envelope is not a processable SAML request | Identity provider | Receive the AuthnRequest | Mandatory. Bindings §3.2.2.1 and §3.2.3.3. `PaosHttpResponse::soap_fault` is HTTP 500 with a Client fault. An empty or blank envelope is not a SOAP envelope: `receive_paos_sso` returns `SamlError::Xml`. SAML-domain failures, including authentication failure, are answered with `RespondPaosSso::failure` |
| Return a SOAP envelope with one `Response` and an `ecp:Response` | Identity provider | Send the response | Mandatory. Profiles §4.2.3.6 and §4.2.4.4. `AssertionConsumerServiceURL` is the request's assertion consumer URL, or the indexed metadata location. A request with neither is answered at the service provider role's default assertion consumer, as Core §3.4.1 requires when the index is omitted; a default that is not HTTP-POST or HTTP-POST-SimpleSign is rejected, as the typed browser response does. A URL or index that the service provider metadata does not publish for HTTP-POST or HTTP-POST-SimpleSign is rejected. The typed browser response applies the same binding rule |
| `ecp:Response` `mustUnderstand` is `1` and `actor` is `http://schemas.xmlsoap.org/soap/actor/next` | Identity provider | Send the response | Mandatory. Profiles §4.2.4.4 |
| A successful response follows the browser SSO response rules, including a bearer assertion with an authentication statement | Identity provider | Send the response | Mandatory. Profiles §4.2.3.6, which applies §4.1.4.2. `respond_paos_sso` uses those producer rules for `RespondPaosSso::success`, whose `NameId` is the assertion subject. `RespondPaosSso::attributes` writes the `AttributeStatement` the same way as `RespondSso::attributes`. `RespondPaosSso::authn_context` writes and checks the authentication context the same way as `RespondSso::authn_context`. `RespondPaosSso::authn_instant` writes and checks `AuthnInstant` the same way as `RespondSso::authn_instant`. A requested `SPNameQualifier` and a requested `Subject` are checked as under the browser SSO producer rules. A CBC-encrypted assertion is covered by a response signature, the same rule as typed HTTP-POST |
| An authentication failure is a SAML error `Response` with no assertions, not a SOAP fault | Identity provider | Send the response | Mandatory. Bindings §3.2.2.1 and §3.3.5.1. `RespondPaosSso::failure` writes the status the caller passes. HTTP status stays 200. The caller chooses a subordinate code such as `AuthnFailed`. A top-level `Success` status returns `SamlError::Invalid` from `respond_paos_sso`: Profiles §4.1.4.2, incorporated by §4.2.3.6, requires an assertion in a successful response |
| Content-Type `text/xml; charset=utf-8` | Identity provider | HTTP response | SOAP 1.1 over HTTP, Bindings §3.2.3 |
| Responder cache headers, as on the service provider | Identity provider | HTTP response | Recommendation. Bindings §3.2.3.2 |

Metadata MAY advertise an `AssertionConsumerService` with binding
`urn:oasis:names:tc:SAML:2.0:bindings:PAOS` and a `SingleSignOnService` with
binding `urn:oasis:names:tc:SAML:2.0:bindings:SOAP` (Errata 05 E20, Profiles
§4.2.6). This exchange does not add those metadata endpoints. The assertion
consumer URL is one the service provider already publishes, and the SOAP
endpoint is the URL passed to `StartPaosSso::new`.
