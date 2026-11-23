//! XML escaping helpers.

/// Escape `& " ' < >` for safe inclusion in XML text or attributes.
#[cfg(any(crypto, test))]
pub(crate) fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_golden() {
        assert_eq!(
            xml_escape("a & b <c> \"d\" 'e'"),
            "a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"
        );
    }
}
