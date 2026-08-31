use std::{env, fs};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 { std::process::exit(64); }
    let bytes = fs::read(&args[1]).unwrap_or_else(|_| std::process::exit(65));
    fs::write(&args[2], bytes).unwrap_or_else(|_| std::process::exit(66));
}
