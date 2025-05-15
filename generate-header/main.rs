use cbindgen::Config;
use std::{env, path::Path};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: generate-header <output>");
        std::process::exit(1);
    }

    let output = Path::new(&args[1]);
    if !output.extension().is_some_and(|h| h == "h") {
        eprintln!("Output must end with .h (got {})", output.display());
        std::process::exit(1);
    }

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config = Config::from_file(Path::new(&crate_dir).join("cbindgen.toml")).expect("expected a cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate_and_name(crate_dir, "signal-tokenizer")
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output);
}
