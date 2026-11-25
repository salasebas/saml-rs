# Send the quoted `SOAPAction` value

`SoapRequest::headers` and `Outbound::headers` for a SOAP request now give
`SOAPAction` the value `"http://www.oasis-open.org/committees/security"`,
with the double quotes. Before, the value was the bare URI. The SOAP 1.1
§6.1.1 header grammar puts the URI in quotes, and WS-I Basic Profile 1.1 lets
a receiver fault on a bare value.

## Who must change

You must change code if your HTTP client adds quotes to the `SOAPAction`
value or compares it with the bare URI. Send the value from `headers()`
unchanged.

Before:

```rust
let action = format!("\"{}\"", header.value());
```

After:

```rust
let action = header.value();
```

Update any gateway or firewall rule that matches the bare value.
