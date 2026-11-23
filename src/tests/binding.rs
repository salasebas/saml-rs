use saml_rs::binding::{deflate_raw_decode, deflate_raw_encode, MAX_DEFLATE_RAW_DECODE_BYTES};
#[test]
fn deflate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let original = b"<samlp:AuthnRequest ID=\"_abc\" Version=\"2.0\"/>";
    let compressed = deflate_raw_encode(original)?;
    let restored = deflate_raw_decode(&compressed, MAX_DEFLATE_RAW_DECODE_BYTES)?;
    assert_eq!(restored, original);
    Ok(())
}
