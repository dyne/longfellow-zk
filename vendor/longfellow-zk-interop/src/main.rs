use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: longfellow-zk-interop --cpp <fixture.lfc2> --rust <fixture.lfc2>");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut cpp = None;
    let mut rust = None;
    while let Some(argument) = args.next() {
        let value = match argument.as_str() {
            "--cpp" => &mut cpp,
            "--rust" => &mut rust,
            _ => usage(),
        };
        *value = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
    }
    let (Some(cpp), Some(rust)) = (cpp, rust) else { usage() };
    if let Err(error) = longfellow_zk_interop::exchange(&cpp, &rust) {
        eprintln!("LFC2 interop failed: {error}");
        std::process::exit(1);
    }
}
