# Axum service provider example

`axum-sp` is a service provider that signs a user in to a protected page
through a local Keycloak, then logs the user out. It uses only the typed
`saml-rs` API: `start_sso`, `finish_sso`, `start_slo`, and `finish_slo`.

The package is not published, and the `saml-rs` crate does not include it.

## Run the tests

The tests need no network, Docker, or Keycloak. An `IdentityProvider` from
`saml-rs` answers the requests in the same process:

```sh
cargo test -p axum-sp
```

## Sign in through Keycloak

You need Docker. Run these commands from the repository root.

1. Start Keycloak 26.6.0 with the committed `saml-rs` realm:

   ```sh
   docker compose -f examples/axum-sp/compose.yaml up -d
   ```

   Keycloak is ready when
   `curl -sf http://127.0.0.1:8080/realms/saml-rs/protocol/saml/descriptor`
   prints the realm metadata.

2. Start the service provider:

   ```sh
   cargo run -p axum-sp
   ```

   The log shows `serving listen_address="127.0.0.1:3000"`.

3. Open `http://localhost:3000/` in a browser. The service provider sends you
   to the Keycloak sign-in page.
4. Sign in as `alice` with the password `alice-password`. The browser returns
   to `http://localhost:3000/` and shows `Signed in as alice@example.com`.
5. Click **Sign out**. Keycloak ends its session and returns you to
   `/saml/slo`, which shows `Signed out`.
6. Stop Keycloak:

   ```sh
   docker compose -f examples/axum-sp/compose.yaml down
   ```

The service provider is at `localhost` and Keycloak is at `127.0.0.1`. They are
two sites, so the browser applies its cross-site cookie rules to the POST that
Keycloak sends to the assertion consumer service. Chrome keeps a `Secure`
cookie that `http://localhost` sets. If your browser drops it, sign-in fails
with `Bad request.` at `/saml/acs`. Serve the service provider over HTTPS
instead.

## Read the log

Each SAML step logs one line with the operation, the request ID, and the
outcome. A refused step also logs the `SamlError` it returned:

```text
INFO operation="start_sso" request_id="_38ad91db2d9518826956cb4eed3fd95aa12cad1b" outcome="sent"
INFO operation="finish_sso" request_id="_38ad91db2d9518826956cb4eed3fd95aa12cad1b" outcome="signed_in" issuer="http://127.0.0.1:8080/realms/saml-rs" assertion_id="ID_c14bcc9b-5952-4f62-a8c4-d5d8735e3488"
WARN operation="start_sso" outcome="error" error=AuthnRequestSigningRequired
WARN operation="finish_sso" outcome="bad_request" reason="the pending-login cookie is missing or differs from RelayState"
```

The request ID is the `AuthnRequest` or `LogoutRequest` ID. Keycloak returns it
as `InResponseTo`. The handlers log no `NameID`, attribute value, or RelayState. The
`Debug` form of a `SamlError` can quote values from the message, such as the
`Destination` URL.

## Configure it

Environment variables override the defaults, which match the committed realm.

| Variable | Default |
| --- | --- |
| `SP_PUBLIC_BASE_URL` | `http://localhost:3000/` |
| `LISTEN_ADDRESS` | `127.0.0.1:3000` |
| `IDP_ENTITY_ID` | `http://127.0.0.1:8080/realms/saml-rs` |
| `IDP_METADATA_FILE` | `keycloak/idp-metadata.xml` |
| `SP_CERTIFICATE_FILE` | `keys/sp-cert.pem` |
| `SP_PRIVATE_KEY_FILE` | `keys/sp-key.pem` |
| `SESSION_MAX_LIFETIME_SECONDS` | `28800` |
| `IDP_LOGOUT_ALLOW_HTTP` | `true` |

The service provider reads the IdP metadata file as trusted, without a
signature. Load it only from a file you control. `IDP_LOGOUT_ALLOW_HTTP=true`
lets logout reach the `http` Keycloak endpoint. Set it to `false` for an IdP
that serves `https`.

The keys in `keys/` and in `keycloak/realm.json` are for this example only.
Anyone can read them, so never use them anywhere else. If you change the realm
key, fetch the metadata again:

```sh
curl -sf http://127.0.0.1:8080/realms/saml-rs/protocol/saml/descriptor \
  > examples/axum-sp/keycloak/idp-metadata.xml
```

## Where each check lives

| Check | Owner |
| --- | --- |
| Signature, issuer, audience, destination, `InResponseTo`, time windows, and replay | `finish_sso` and `finish_slo` in `saml-rs` |
| The pending login belongs to the browser that started it | The `saml_pending` cookie, which holds the RelayState and must match the posted RelayState |
| Each pending login and logout finishes once and expires after ten minutes | The in-memory stores in `src/store.rs` |
| One replay cache for every ACS request | `main.rs` builds one `InMemoryReplayCache` and passes it to `router` |
| Login returns only to this origin | `src/return_url.rs` resolves `return` with `Url::join` |
| A session ends at the maximum lifetime, or at an earlier `SessionNotOnOrAfter` | The ACS handler in `src/handlers.rs` |
| TLS, and limits on how many logins one client may start | The deployment |

Pending requests, sessions, and the replay cache live in one process and are
lost on restart. To run several processes, keep them in storage that every
process shares, and implement `ReplayCache` on it.
