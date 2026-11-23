//! Robustness / fuzz-lite tests: the parser, extractor and codecs must never
//! panic on hostile input, and DEFLATE must round-trip. Dependency-free
//! (deterministic LCG instead of a property-testing crate).

use saml_rs::binding::{deflate_raw_decode, deflate_raw_encode, MAX_DEFLATE_RAW_DECODE_BYTES};
use saml_rs::xml::dom::parse_document;
use saml_rs::xml::{extract, ExtractorField};

fn lcg(seed: &mut u64) -> u8 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 33) as u8
}

#[test]
fn malformed_xml_inputs_never_panic() {
    let nasty = [
        "",
        "   ",
        "<",
        "<a",
        "<a>",
        "<a></b>",
        "<!DOCTYPE x [<!ENTITY e \"x\">]><x/>",
        "<a>&undefined;</a>",
        "<a><a><a></a></a>",
        "not xml at all",
        "<?xml?>",
        "<a x=>",
        "<a x=\"unclosed>",
        "<a><![CDATA[unterminated",
        "<a><!-- unterminated",
        "<a:b xmlns:a=\"urn:x\"/>",
        "<\u{0}\u{0}/>",
        "<삼성>x</삼성>",
        "<a>\u{1}\u{2}\u{3}</a>",
    ];
    let fields = [
        ExtractorField::new("x", &["a"]),
        ExtractorField::new("r", &["Response", "Assertion"]).capture_source(),
    ];
    for input in nasty {
        let _ = parse_document(input, saml_rs::XmlLimits::default());
        let _ = extract(input, &fields);
    }
}

#[test]
fn pseudo_random_inputs_never_panic() {
    let mut seed = 0x0123_4567_89ab_cdefu64;
    let fields = [ExtractorField::new(
        "x",
        &["Response", "Assertion", "Subject"],
    )];
    for _ in 0..1000 {
        let len = (lcg(&mut seed) % 128) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            // Bias toward XML-ish bytes so the parser exercises real paths.
            let b = match lcg(&mut seed) % 8 {
                0 => b'<',
                1 => b'>',
                2 => b'/',
                3 => b'"',
                4 => b'&',
                _ => b'!' + (lcg(&mut seed) % 90),
            };
            s.push(b as char);
        }
        let _ = parse_document(&s, saml_rs::XmlLimits::default());
        let _ = extract(&s, &fields);
    }
}

#[test]
fn moderately_deep_nesting_does_not_overflow() {
    let deep = format!("{}{}", "<a>".repeat(800), "</a>".repeat(800));
    let _ = parse_document(&deep, saml_rs::XmlLimits::default());
    let _ = extract(&deep, &[ExtractorField::new("a", &["a"])]);
}

#[test]
fn deflate_roundtrips_for_arbitrary_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = 0xdead_beef_u64;
    for len in [0usize, 1, 7, 64, 1000, 4096] {
        let data: Vec<u8> = (0..len).map(|_| lcg(&mut seed)).collect();
        let restored =
            deflate_raw_decode(&deflate_raw_encode(&data)?, MAX_DEFLATE_RAW_DECODE_BYTES)?;
        assert_eq!(restored, data);
    }
    Ok(())
}
