---
title: "Logout expiration"
description: "`Saml<Idp>::start_slo` models a SAML session authority, so it emits `LogoutRequest@NotOnOrAfter`. The deadline uses the same identity-provider issuance lifetime as generated..."
---

`Saml<Idp>::start_slo` models a SAML session authority, so it emits `LogoutRequest@NotOnOrAfter`. The deadline uses the same identity-provider issuance lifetime as generated assertion time bounds. The default is five minutes. A later logout deadline is then no earlier than assertion bounds from that same `Saml<Idp>`.

The OASIS recommendation compares `NotOnOrAfter` with the assertion most recently issued for the session. This operation does not receive that assertion. The issuance lifetime does not claim an ordering against arbitrary historical, custom, or proxied assertions.

The attribute cannot be turned off on the typed session-authority flow. A session participant does not synthesize `NotOnOrAfter`. The five-minute value is library policy, not an OASIS duration.

SAML Core 2.0 section 3.7.3.2 requires a session authority constructing a `LogoutRequest` to set `NotOnOrAfter`. Core section 3.7.1 describes that attribute as optional on the generic `LogoutRequest`, and the protocol schema declares it with `use="optional"`. Approved Errata 05 E38 clarifies `SessionIndex` and does not change either rule.

The call is in [Single Logout](../guides/single-logout.md). This page restates [ADR 0001](https://github.com/salasebas/saml-rs/blob/main/docs/adr/0001-session-authority-logout-expiration.md).
