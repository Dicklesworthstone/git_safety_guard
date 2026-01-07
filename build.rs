//! Build script for `git_safety_guard`.
//!
//! Embeds build metadata (timestamp, git commit, rustc version) into the binary
//! for display in --version output and debugging.

use vergen_gix::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder};

fn main() {
    // Emit build metadata as environment variables at compile time
    let build = BuildBuilder::default().build_timestamp(true).build();

    let cargo = CargoBuilder::default().target_triple(true).build();

    let rustc = RustcBuilder::default().semver(true).build();

    let mut emitter = Emitter::default();

    // Add build, cargo, and rustc instructions if available
    if let Ok(b) = build {
        if let Err(e) = emitter.add_instructions(&b) {
            eprintln!("cargo:warning=vergen build instructions failed: {e}");
        }
    }

    if let Ok(c) = cargo {
        if let Err(e) = emitter.add_instructions(&c) {
            eprintln!("cargo:warning=vergen cargo instructions failed: {e}");
        }
    }

    if let Ok(r) = rustc {
        if let Err(e) = emitter.add_instructions(&r) {
            eprintln!("cargo:warning=vergen rustc instructions failed: {e}");
        }
    }

    // Emit all collected instructions
    if let Err(e) = emitter.emit() {
        eprintln!("cargo:warning=vergen emit failed: {e}");
    }
}
