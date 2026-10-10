# Limited base64 decoding rejects non-ASCII whitespace

This break is unreleased. It applies to `base64_decode_with_limit`.

The size check and the decoder now ignore the same ASCII whitespace: space,
tab, line feed, form feed, and carriage return. A byte outside that set and
outside the base64 alphabet is rejected. That includes Unicode spaces such as
U+00A0 and U+2028, and vertical tab.

Who must change: callers who decode base64 that contains those characters.
HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign inbound messages use this
decoder.

Remove the extra characters, or send standard base64. ASCII whitespace may
still appear between encoded characters. `base64_decode` is unchanged.
