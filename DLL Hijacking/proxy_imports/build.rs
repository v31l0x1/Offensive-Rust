use std::{env, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let def_path = PathBuf::from(manifest_dir).join("exports.def");
        println!("cargo:rustc-link-arg=/DEF:{}", def_path.display());
        println!("cargo:rerun-if-changed=exports.def");
    }
}
