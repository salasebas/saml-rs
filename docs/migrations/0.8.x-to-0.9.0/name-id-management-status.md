# Handle relative status codes in name identifier management responses

If you answer a `ManageNameIDRequest`, `IdentityProvider::respond_name_id_management`,
`IdentityProvider::respond_name_id_management_redirect`, and
`ServiceProvider::respond_name_id_management_redirect` now return
`SamlError::Invalid` when `status` has a subordinate code that is not an
absolute URI. Before, the response carried that code.

`SubordinateStatusCode::try_new` already refuses such a code, so a status you
build yourself is not affected. A status you read from a peer can have one:
`SamlError::StatusNotSuccess` keeps a received subordinate code as sent, for
example from `StartedNameIdManagement::finish` or
`finish_name_id_management_redirect`.

To upgrade, do not pass a received `Status` to a response unchanged. Build
the status you send from `Status::requester`, `Status::responder`, or
`Status::success`, and add a subordinate code with
`SubordinateStatusCode::try_new` or a constructor such as
`SubordinateStatusCode::unknown_principal`.
