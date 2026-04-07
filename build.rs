use std::env;
use std::process::Command;

fn main() {
    // 1. Check if we are in CircleCI (or explicitly skipping)
    if env::var("CIRCLECI").is_ok() || env::var("SKIP_LCSF_GEN").is_ok() {
        // Print a warning to the build logs so you know it was skipped
        println!("cargo:warning=Skipping LCSF code generation in CI environment.");
        return; // Exit build.rs early, allowing Cargo to compile normally
    }

    let lcsf_gen_bin = "../LCSF_Generator/build/bin/lcsf_generator_cli";
    let test_prot_desc = "../LCSF_Generator/example/Test.json";
    let rust_prot_a = "./src/lcsf_prot/protocol_test_a.rs";

    // Tell Cargo to re-run this build script ONLY if the JSON file
    // or the generator binary changes. This saves compilation time.
    println!("cargo:rerun-if-changed={}", test_prot_desc);
    println!("cargo:rerun-if-changed={}", lcsf_gen_bin);

    // 1. Run the Generator
    let status = Command::new(lcsf_gen_bin)
        .arg("-l")
        .arg(test_prot_desc)
        .arg("--ra")
        .arg(rust_prot_a)
        .status()
        .expect("Failed to execute LCSF generator");

    assert!(status.success(), "Generator failed");
}
