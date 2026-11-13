fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(crypto)");
    if [
        "CARGO_FEATURE_CRYPTO_RUSTCRYPTO",
        "CARGO_FEATURE_CRYPTO_AWS_LC",
        "CARGO_FEATURE_CRYPTO_FIPS",
    ]
    .iter()
    .any(|feature| std::env::var_os(feature).is_some())
    {
        println!("cargo::rustc-cfg=crypto");
    }
}
