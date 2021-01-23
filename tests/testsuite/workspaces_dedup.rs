//! Tests for inheriting fields in a workspace member's Cargo.toml with { workspace = true }

use cargo_test_support::{basic_manifest, project};

#[cargo_test]
fn virtual_all_fields_no_inherit() {
    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [workspace]
                members = ["bar"]
                version = "1.2.3"
                authors = ["Rustaceans"]
                description = "This is a test crate"
                documentation = "https://www.rust-lang.org/learn"
                readme = "README.md"
                homepage = "https://www.rust-lang.org"
                repository = "https://github.com/example/example"
                license = "MIT"
                license-file = "./LICENSE"
                keywords = ["cli"]
                categories = ["development-tools"]
                publish = false
                edition = "2018"

                [workspace.badges]
                gitlab = { repository = "https://gitlab.com/rust-lang/rust", branch = "master" }

                [workspace.dependencies]
                dep = "0.1"
            "#,
        )
        .file("bar/Cargo.toml", &basic_manifest("bar", "0.1.0"))
        .file("bar/src/main.rs", "fn main() {}");

    let p = p.build();
    p.cargo("build").cwd("bar").run();
    assert!(p.root().join("Cargo.lock").is_file());
    assert!(p.bin("bar").is_file());
    assert!(!p.root().join("bar/Cargo.lock").is_file());
}