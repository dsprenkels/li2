extern crate bindgen;
extern crate cc;

use std::path::PathBuf;

fn main() {
    let modes = ["2", "3", "5"];

    // Compile all dilithium implementations
    let files = &[
        "crystals-dilithium/ref/sign.c",
        "crystals-dilithium/ref/packing.c",
        "crystals-dilithium/ref/polyvec.c",
        "crystals-dilithium/ref/poly.c",
        "crystals-dilithium/ref/ntt.c",
        "crystals-dilithium/ref/reduce.c",
        "crystals-dilithium/ref/rounding.c",
        "crystals-dilithium/ref/symmetric-shake.c",
    ];
    for mode in modes {
        cc::Build::new()
            .shared_flag(true)
            .static_flag(true)
            .define("DILITHIUM_MODE", &format!("{}", mode)[..])
            .include("crystals-dilithium/ref")
            .files(files)
            .compile(&format!("dilithium{}", mode)[..]);
    }
    for file in files {
        println!("cargo:rerun-if-changed={}", file);
    }

    // Compile fips202 package
    cc::Build::new()
        .shared_flag(true)
        .static_flag(true)
        .include("crystals-dilithium/ref")
        .file("crystals-dilithium/ref/fips202.c")
        .compile("fips202");
    println!("crystals-dilithium/ref/fips202.c");

    // Compile deterministic rng
    cc::Build::new()
        .shared_flag(true)
        .static_flag(true)
        .include("crystals-dilithium/ref")
        .file("crystals-dilithium/ref/rng.c")
        .compile("rng");
    println!("crystals-dilithium/ref/rng.c");

    // Link openssl because of the AES primitive used in rng.c
    println!("cargo:rustc-link-lib=crypto");

    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for mode in modes {
        let bindings = bindgen::Builder::default()
            .use_core()
            .header_contents(
                &format!("dilithium{}_wrapper.h", mode)[..],
                &format!("#define DILITHIUM_MODE {}", mode)[..],
            )
            .header("wrapper.h")
            .derive_default(true)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");
        bindings
            .write_to_file(out_path.join(format!("bindings_dilithium{}.rs", mode)))
            .expect("Couldn't write bindings!");
    }
    println!("cargo:rerun-if-changed=wrapper.h");
}
