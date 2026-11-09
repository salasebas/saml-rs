//! XML Schema `xs:anyURI` values that must be absolute URI references.
//!
//! The lexical mapping is XML Schema 1.0 Part 2 §3.2.17 and §4.3.6: whitespace
//! collapse, then the XLink 1.0 §5.4 escaping, then a URI reference of RFC 2396
//! as amended by RFC 2732.

use std::net::Ipv6Addr;

/// Whether `value` is a non-empty absolute URI reference once read as an
/// `xs:anyURI`.
///
/// A fragment is allowed. Characters that XLink escaping turns into `%HH`,
/// such as a space, `<`, or a non-ASCII letter, are accepted where an escaped
/// octet is. Characters that XML 1.0 cannot carry are rejected.
pub(crate) fn is_absolute_uri_reference(value: &str) -> bool {
    value.chars().all(is_xml_char)
        && is_absolute_uri_reference_ascii(&escape_disallowed(&collapse_whitespace(value)))
}

/// The `xs:anyURI` whitespace collapse: XML whitespace runs become one space,
/// and leading and trailing whitespace is removed.
pub(crate) fn collapse_whitespace(value: &str) -> String {
    value
        .split(is_xml_whitespace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_xml_whitespace(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\n' | '\r')
}

fn is_xml_char(value: char) -> bool {
    matches!(
        value,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..
    )
}

/// XLink 1.0 §5.4: non-ASCII characters and the RFC 2396 §2.4.3 excluded
/// characters, except `#` and `%`, become `%HH` UTF-8 octets. RFC 2732 takes
/// `[` and `]` out of that set.
fn escape_disallowed(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if is_disallowed(character) {
            let mut buffer = [0; 4];
            for byte in character.encode_utf8(&mut buffer).bytes() {
                escaped.push_str(&format!("%{byte:02X}"));
            }
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn is_disallowed(value: char) -> bool {
    !value.is_ascii()
        || value.is_ascii_control()
        || matches!(
            value,
            ' ' | '<' | '>' | '"' | '{' | '}' | '|' | '\\' | '^' | '`'
        )
}

/// RFC 2396 `absoluteURI [ "#" fragment ]`.
fn is_absolute_uri_reference_ascii(value: &str) -> bool {
    let (uri, fragment) = match value.split_once('#') {
        Some((uri, fragment)) => (uri, Some(fragment)),
        None => (value, None),
    };
    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    is_scheme(scheme)
        && (is_hier_part(rest) || is_opaque_part(rest))
        && fragment.is_none_or(|fragment| all_allowed(fragment, is_uric))
}

/// `alpha *( alpha | digit | "+" | "-" | "." )`.
fn is_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// `( net_path | abs_path ) [ "?" query ]`.
fn is_hier_part(value: &str) -> bool {
    let (path, query) = match value.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (value, None),
    };
    let path_is_valid = match path.strip_prefix("//") {
        Some(net_path) => {
            let (authority, abs_path) =
                net_path.split_at(net_path.find('/').unwrap_or(net_path.len()));
            is_authority(authority) && (abs_path.is_empty() || is_abs_path(abs_path))
        }
        None => is_abs_path(path),
    };
    path_is_valid && query.is_none_or(|query| all_allowed(query, is_uric))
}

/// `"/" path_segments`, where a segment is `*pchar *( ";" param )`.
fn is_abs_path(value: &str) -> bool {
    value.starts_with('/')
        && all_allowed(value, |byte| is_pchar(byte) || matches!(byte, b'/' | b';'))
}

/// `uric_no_slash *uric`.
fn is_opaque_part(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|first| first != b'/' && first != b'[' && first != b']')
        && all_allowed(value, is_uric)
}

/// `server | reg_name`. A server may be empty, and only a server carries an
/// RFC 2732 `IPv6reference`.
fn is_authority(value: &str) -> bool {
    if !value.contains(['[', ']']) {
        return all_allowed(value, is_reg_name_char);
    }
    let (userinfo, host_port) = match value.split_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, value),
    };
    let Some((address, port)) = host_port
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    else {
        return false;
    };
    userinfo.is_none_or(|userinfo| all_allowed(userinfo, is_userinfo_char))
        && address.parse::<Ipv6Addr>().is_ok()
        && (port.is_empty()
            || port
                .strip_prefix(':')
                .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit())))
}

/// Every octet satisfies `allowed`, or starts an `escaped` `"%" hex hex`.
fn all_allowed(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        let valid = if byte == b'%' {
            bytes.next().is_some_and(|high| high.is_ascii_hexdigit())
                && bytes.next().is_some_and(|low| low.is_ascii_hexdigit())
        } else {
            allowed(byte)
        };
        if !valid {
            return false;
        }
    }
    true
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}

fn is_uric(byte: u8) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' | b'[' | b']'
        )
}

fn is_pchar(byte: u8) -> bool {
    is_unreserved(byte) || matches!(byte, b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',')
}

fn is_reg_name_char(byte: u8) -> bool {
    is_unreserved(byte) || matches!(byte, b'$' | b',' | b';' | b':' | b'@' | b'&' | b'=' | b'+')
}

fn is_userinfo_char(byte: u8) -> bool {
    is_unreserved(byte) || matches!(byte, b';' | b':' | b'&' | b'=' | b'+' | b'$' | b',')
}

#[cfg(test)]
mod tests {
    use super::{collapse_whitespace, is_absolute_uri_reference};

    #[test]
    fn accepts_absolute_uri_references() {
        for value in [
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "urn:example:name-id-format",
            "https://example.com/name-id-format",
            "https://user:pw@example.com:8443/a;b/c?d=e&f#g",
            "http://[2001:db8::1]:8080/format",
            "file:///tmp/format",
            "http://",
            "mailto:alice@example.com",
            "urn:example:a?b[c]",
            "urn:example:%41",
            "urn:example:fragment#part",
            // XLink escaping turns these into %HH octets.
            "urn:example:a<b\"c>d",
            "urn:example:caf\u{e9}",
            "urn:example:a b",
            "urn:example:a\tb",
            " urn:example:padded ",
        ] {
            assert!(is_absolute_uri_reference(value), "{value:?}");
        }
    }

    #[test]
    fn rejects_blank_relative_and_malformed_values() {
        for value in [
            "",
            " ",
            "\t\r\n",
            "local-format",
            "/relative/path",
            "#fragment",
            "urn:",
            "1urn:example",
            "ur n:example",
            ":example",
            "urn:%zz",
            "urn:%4",
            "urn:a#b#c",
            "urn:[a]",
            "http://exa[mple].com/",
            "http://[not-an-address]/",
            "http://[::1]x/",
            "http://[::1]:80a/",
            "http://example.com/a[b]",
            "urn:example:\u{1}",
            "urn:example:\u{fffe}",
        ] {
            assert!(!is_absolute_uri_reference(value), "{value:?}");
        }
    }

    #[test]
    fn collapses_xml_whitespace_only() {
        assert_eq!(collapse_whitespace("\t a \r\n b  "), "a b");
        assert_eq!(collapse_whitespace("a\u{a0}b"), "a\u{a0}b");
    }
}
