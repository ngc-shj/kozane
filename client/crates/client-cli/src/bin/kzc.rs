//! `kzc keygen` (once, as root) and `kzc up` (the `kozane-net` unit).

use std::process::ExitCode;

use kozane_client_cli::seams::Env;
use kozane_client_cli::{build_info, exit, keygen, net};

const USAGE: &str = "usage: kzc keygen | kzc up | kzc --build-info";

fn main() -> ExitCode {
    let (env, args) = match Env::from_args(std::env::args().skip(1).collect()) {
        Ok(x) => x,
        Err(e) => return exit("kzc", Err(e)),
    };
    let r = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen"] => keygen::run(&env),
        ["up"] => net::run(&env),
        ["--build-info"] => {
            println!("{}", build_info());
            Ok(())
        }
        _ => Err(USAGE.into()),
    };
    exit("kzc", r)
}
