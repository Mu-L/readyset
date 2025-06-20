//! Inspired by the crate of the same name in rust-analyzer.
//! https://github.com/rust-analyzer/rust-analyzer/blob/master/crates/test_utils/src/lib.rs

pub use test_utils_proc_macros::{skip_flaky_finder, slow, tags};

// Re-export serial_test so we only need to add `readyset_utils` to `Cargo.toml` for packages that
// use it.
pub use serial_test;

// Re-export pretty_assertions for similar reasons.
pub use pretty_assertions;

/// Returns `false` if slow tests should not run, otherwise returns `true`.
pub fn skip_slow_tests() -> bool {
    let should_skip = std::env::var("RUN_SLOW_TESTS").is_err();
    if should_skip {
        eprintln!("ignoring slow test");
    }
    should_skip
}

/// Returns `true` if the test should be skipped with flaky finder enabled,
/// otherwise returns `false`.
pub fn skip_with_flaky_finder() -> bool {
    let should_skip = std::env::var("FLAKY_FINDER").is_ok();
    if should_skip {
        eprintln!("ignoring flaky_finder test");
    }
    should_skip
}
