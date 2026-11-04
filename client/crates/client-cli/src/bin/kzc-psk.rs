//! `kzc-psk` (the `kozane-psk` unit) and `kzc-psk cleanup` (its
//! `ExecStopPost=`).

use std::process::ExitCode;

use kozane_client_cli::seams::Env;
use kozane_client_cli::{build_info, exit, psk};

const USAGE: &str = "usage: kzc-psk | kzc-psk cleanup | kzc-psk --build-info";

fn main() -> ExitCode {
    let (env, args) = match Env::from_args(std::env::args().skip(1).collect()) {
        Ok(x) => x,
        Err(e) => return exit("kzc-psk", Err(e)),
    };
    let r = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => psk::run(&env),
        ["cleanup"] => psk::cleanup(&env),
        ["--build-info"] => {
            println!("{}", build_info());
            Ok(())
        }
        _ => Err(USAGE.into()),
    };
    exit("kzc-psk", r)
}
