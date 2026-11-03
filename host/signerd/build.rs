fn main() {
    println!("cargo:rerun-if-env-changed=ENCLAVE_U_DIR");
    println!("cargo:rerun-if-env-changed=SGX_SDK");
    if std::env::var("CARGO_FEATURE_SGX").is_ok() {
        let u = std::env::var("ENCLAVE_U_DIR").expect("ENCLAVE_U_DIR=<dir holding libenclave_u.a> for the sgx feature");
        let sdk = std::env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".into());
        println!("cargo:rustc-link-search=native={u}");
        println!("cargo:rustc-link-lib=static=enclave_u");
        println!("cargo:rustc-link-search=native={sdk}/lib64");
        println!("cargo:rustc-link-lib=dylib=sgx_urts");
    }
}
