pub(crate) fn build_simplesign_octet(
    param_name: &str,
    xml: &str,
    relay_state: Option<&str>,
    sig_alg: &str,
) -> String {
    match relay_state {
        Some(relay_state) => {
            format!("{param_name}={xml}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("{param_name}={xml}&SigAlg={sig_alg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::build_simplesign_octet;

    #[test]
    fn simplesign_octet_omits_absent_relay_state() {
        assert_eq!(
            build_simplesign_octet("SAMLRequest", "<xml/>", None, "alg"),
            "SAMLRequest=<xml/>&SigAlg=alg"
        );
    }

    #[test]
    fn simplesign_octet_preserves_explicit_empty_relay_state() {
        assert_eq!(
            build_simplesign_octet("SAMLRequest", "<xml/>", Some(""), "alg"),
            "SAMLRequest=<xml/>&RelayState=&SigAlg=alg"
        );
    }

    #[test]
    fn simplesign_octet_includes_present_relay_state() {
        assert_eq!(
            build_simplesign_octet("SAMLResponse", "<xml/>", Some("state"), "alg"),
            "SAMLResponse=<xml/>&RelayState=state&SigAlg=alg"
        );
    }
}
