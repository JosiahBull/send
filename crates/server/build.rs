//! The build script for the server crate.

use vergen::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder, SysinfoBuilder};
use vergen_gitcl::GitclBuilder;

fn main() {
    let build = BuildBuilder::all_build().expect("Unable to get the build information");
    let cargo = CargoBuilder::all_cargo().expect("Unable to get the cargo information");
    let rustc = RustcBuilder::all_rustc().expect("Unable to get the rustc information");
    let si = SysinfoBuilder::all_sysinfo().expect("Unable to get the sysinfo information");
    let git = GitclBuilder::all_git().expect("Unable to get the git information");

    Emitter::default()
        .add_instructions(&build)
        .expect("Unable to generate the vergen information for the build")
        .add_instructions(&cargo)
        .expect("Unable to generate the vergen information for the cargo")
        .add_instructions(&rustc)
        .expect("Unable to generate the vergen information for the rustc")
        .add_instructions(&si)
        .expect("Unable to generate the vergen information for the sysinfo")
        .add_instructions(&git)
        .expect("Unable to generate the vergen information for the git")
        .emit()
        .expect("Unable to generate the vergen information");
}
