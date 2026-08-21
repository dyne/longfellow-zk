// Independently produces the C++-comparable report using vendored Rust tooling.
use std::{env, fs};

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(1469598103934665603u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(1099511628211)
    })
}

fn main() {
    for path in env::args().skip(1) {
        let bytes = fs::read(&path).expect("compatibility artifact must be readable");
        println!("{}\t{}\t{:016x}", path, bytes.len(), fnv1a(&bytes));
    }
}
