//! `justsign` operator binary. Thin dispatcher — every command
//! lives in [`cli`] (the lib half of this crate) so integration
//! tests can call the same code paths without spawning a process.

use std::io::{self, Write};
use std::process::ExitCode;

use cli::{
    cmd_generate_key_pair, cmd_public_key, cmd_sign_blob, cmd_verify_blob, print_usage, CliError,
};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();

    let result = match argv.get(1).map(String::as_str) {
        Some("generate-key-pair") => cmd_generate_key_pair(&argv[2..], &mut out),
        Some("public-key") => cmd_public_key(&argv[2..], &mut out),
        Some("sign-blob") => cmd_sign_blob(&argv[2..], &mut out),
        Some("verify-blob") => cmd_verify_blob(&argv[2..], &mut out),
        Some("--help") | Some("-h") | Some("help") | None => {
            let _ = print_usage(&mut err);
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(CliError(format!("unknown command: {other} (try --help)"))),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(err, "error: {e}");
            ExitCode::FAILURE
        }
    }
}
