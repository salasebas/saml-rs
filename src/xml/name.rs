//! XML name datatypes: `xs:NCName` and `xs:Name`.
//!
//! Both use the XML 1.0 Fifth Edition name characters.

fn is_name_start_char(value: char) -> bool {
    matches!(
        value,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{c0}'..='\u{d6}'
            | '\u{d8}'..='\u{f6}'
            | '\u{f8}'..='\u{2ff}'
            | '\u{370}'..='\u{37d}'
            | '\u{37f}'..='\u{1fff}'
            | '\u{200c}'..='\u{200d}'
            | '\u{2070}'..='\u{218f}'
            | '\u{2c00}'..='\u{2fef}'
            | '\u{3001}'..='\u{d7ff}'
            | '\u{f900}'..='\u{fdcf}'
            | '\u{fdf0}'..='\u{fffd}'
            | '\u{10000}'..='\u{effff}'
    )
}

fn is_name_char(value: char) -> bool {
    is_name_start_char(value)
        || matches!(
            value,
            '-' | '.'
                | '0'..='9'
                | '\u{b7}'
                | '\u{300}'..='\u{36f}'
                | '\u{203f}'..='\u{2040}'
        )
}

/// Whether `value` is an `xs:NCName`: an XML name without a colon.
pub(crate) fn is_ncname(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(is_name_start_char) && chars.all(is_name_char)
}

/// Whether `value` is an `xs:Name`: an XML name, where a colon is a name
/// character.
pub(crate) fn is_name(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == ':' || is_name_start_char(first))
        && chars.all(|character| character == ':' || is_name_char(character))
}

#[cfg(test)]
mod tests {
    use super::{is_name, is_ncname};

    #[test]
    fn name_allows_a_colon_and_ncname_does_not() {
        for value in ["mail", "_mail", "given-name.1", "\u{e9}t\u{e9}"] {
            assert!(is_name(value), "{value}");
            assert!(is_ncname(value), "{value}");
        }
        for value in ["ns:mail", ":mail"] {
            assert!(is_name(value), "{value}");
            assert!(!is_ncname(value), "{value}");
        }
        for value in ["", "1mail", "-mail", ".mail", "given name", "a<b"] {
            assert!(!is_name(value), "{value:?}");
            assert!(!is_ncname(value), "{value:?}");
        }
    }
}
