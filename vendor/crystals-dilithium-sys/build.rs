extern crate bindgen;
extern crate cc;

use std::path::PathBuf;

fn main() {
    const MODES: [&str; 3] = ["2", "3", "5"];

    println!("cargo:rerun-if-changed=wrapper.h");

    for mode in MODES {
        cc::Build::new()
            .shared_flag(true)
            .static_flag(true)
            .define("DILITHIUM_MODE", &format!("{}", mode)[..])
            .include("crystals-dilithium/ref")
            .files(&[
                "crystals-dilithium/ref/sign.c",
                "crystals-dilithium/ref/packing.c",
                "crystals-dilithium/ref/polyvec.c",
                "crystals-dilithium/ref/poly.c",
                "crystals-dilithium/ref/ntt.c",
                "crystals-dilithium/ref/reduce.c",
                "crystals-dilithium/ref/rounding.c",
            ])
            .compile(&format!("dilithium{}", mode)[..]);
    }

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    for mode in MODES {
        // The bindgen::Builder is the main entry point
        // to bindgen, and lets you build up options for
        // the resulting bindings.
        let bindings = bindgen::Builder::default()
            // The input header we would like to generate
            // bindings for.
            .header_contents(
                &format!("dilithium{}_wrapper.h", mode)[..],
                &format!("#define DILITHIUM_MODE {}", mode)[..],
            )
            .header("wrapper.h")
            // .define("DILITHIUM_MODE", &format!("{}", mode)[..])
            // Tell cargo to invalidate the built crate whenever any of the
            // included header files changed.
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            // Finish the builder and generate the bindings.
            .generate()
            // Unwrap the Result and panic on failure.
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join(format!("bindings_dilithium{}.rs", mode)))
            .expect("Couldn't write bindings!");
    }
}
