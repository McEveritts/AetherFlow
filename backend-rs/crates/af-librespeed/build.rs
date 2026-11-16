fn main() {
    println!("cargo:rerun-if-env-changed=AF_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=AETHERFLOW_VERSION");

    let fallback = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "4.0.0".to_string());
    let effective = std::env::var("AF_BUILD_VERSION")
        .ok()
        .or_else(|| std::env::var("AETHERFLOW_VERSION").ok())
        .map(|raw| raw.trim().trim_start_matches('v').to_string())
        .filter(|val| !val.is_empty())
        .unwrap_or(fallback);

    println!("cargo:rustc-env=AF_LIBRESPEED_EFFECTIVE_VERSION={effective}");
}
