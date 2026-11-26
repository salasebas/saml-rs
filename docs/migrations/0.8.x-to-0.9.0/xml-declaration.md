# Handle documents with a malformed XML declaration

This change affects code that receives SAML messages, SOAP envelopes, or
metadata. No code fails to compile.

saml-rs now checks the XML declaration at the start of every received
document against the `XMLDecl` production of XML 1.0. The declaration must
start with `version`, followed by `encoding` and then `standalone` when they
appear. Each pseudo-attribute appears at most once, and no other one is
allowed. saml-rs 0.8 checked only where the declaration stood, so it accepted
a received message or metadata document with a declaration such as
`<?xml version="1.0" garbage="yes"?>` or
`<?xml encoding="UTF-8" version="1.0"?>`. That document now fails with
`SamlError::Xml`. A received SOAP envelope fails with
`SamlError::SoapEnvelope` with the `Client` fault code, and its source is the
XML error.

A document without a declaration, or with a declaration such as
`<?xml version="1.0" encoding="UTF-8"?>`, is read as before. If a peer sends a
malformed declaration, ask the peer to fix it.
