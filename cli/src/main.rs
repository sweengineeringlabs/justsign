//! `justsign` operator binary — thin dispatcher.
//!
//! Stub. The subcommand surface lands in subsequent slices.

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let stderr = io::stderr();
    let mut err = stderr.lock();
    let _ = writeln!(
        err,
        "justsign: pre-v0; subcommand surface not yet wired. \
         Watch https://github.com/sweengineeringlabs/justsign."
    );
    ExitCode::from(2)
}
