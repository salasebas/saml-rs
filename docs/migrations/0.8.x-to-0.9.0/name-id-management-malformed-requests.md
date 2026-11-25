# Answer malformed name identifier management requests

If you receive `ManageNameIDRequest` messages,
`IdentityProvider::receive_name_id_management` and
`receive_name_id_management_redirect` on both providers now return
`NameIdManagementReceipt::Refused` with
`NameIdManagementRefusal::MalformedRequest` for an authenticated request
whose identifier and change do not follow `ManageNameIDRequestType`. For
example, the request has no `Terminate` or `NewID`, has two identifiers, or
has elements out of schema order. Before, these methods returned
`SamlError::ProtocolProfile`, and you answered with a SOAP fault or not at all.

The refusal carries a `ManageNameIDResponse` with a `Requester` status, as
Profiles §4.5.3.2 requires for an error. `RefusedNameIdManagement::content_error`
returns the error that the methods returned before.

To upgrade, send `refused.response()` as you do for the other refusals. If
you match `refused.reason()` exhaustively, add the `MalformedRequest` arm; the
enum is `#[non_exhaustive]`, so a wildcard arm already covers it.

These requests still return an error:

- A request that is not authenticated, not from the peer, or sent to another
  endpoint.
- A request that a configured `SchemaValidator` rejects. The validator runs
  before these checks.
- A repeated request `ID` that the replay cache holds. Over SOAP, the cache
  holds only accepted requests, so a repeated malformed request is refused
  again. Over HTTP-Redirect, a request inside the age window is checked for
  replay before it is refused.
