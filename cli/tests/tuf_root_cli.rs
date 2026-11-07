//! End-to-end tests for `sign tuf-root show|verify` (issue #35).
//!
//! These spawn the real `sign` binary, so they pin what operators and
//! scripts actually observe: stdout and the process exit code.
//!
//! Exit codes under test: 0 ok, 1 usage/IO, 3 malformed, 4 expired,
//! 5 signature below threshold.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sign::tuf;

/// Real Sigstore v14 root, expired 2026-06-22. A permanently expired,
/// otherwise genuine root: it cannot start passing as time goes on.
const EXPIRED_ROOT: &[u8] = include_bytes!("fixtures/sigstore_v14_expired.root.json");

fn sign(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sign"))
        .args(args)
        .output()
        .expect("sign binary must spawn")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("process exited with a code")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Write `bytes` to a unique file under cargo's per-test tmp dir.
fn write_tmp(tag: &str, bytes: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tuf_root_cli");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let path = dir.join(format!("{}-{tag}.json", std::process::id()));
    std::fs::write(&path, bytes).expect("write tmp file");
    path
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// The bundled root with its `expires` year bumped by one digit. The
/// envelope still parses and is not expired, but the root's own
/// signatures no longer cover what it says.
fn tampered_bundled_root() -> Vec<u8> {
    let mut bytes = tuf::SIGSTORE_PRODUCTION_ROOT_BYTES.to_vec();
    let needle = b"\"expires\": \"";
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("bundled root has an expires field")
        + needle.len();
    assert!(
        bytes[pos].is_ascii_digit() && bytes[pos] != b'9',
        "the first digit of the year must be bumpable"
    );
    bytes[pos] += 1;
    bytes
}

// ---- show ----------------------------------------------------------

/// Bug it catches: `show` printing the wrong constant, dropping one, or
/// reordering them, which breaks scripts that parse it and makes release
/// diffs noisy.
#[test]
fn test_tuf_root_show_prints_five_fields_in_stable_order() {
    let out = sign(&["tuf-root", "show"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let text = stdout(&out);
    let keys: Vec<&str> = text
        .lines()
        .map(|l| l.split(':').next().expect("key before colon"))
        .collect();
    assert_eq!(
        keys,
        ["version", "sha256", "source", "fetched_at", "expires"],
        "fields and their order are a stable interface:\n{text}"
    );

    assert!(text.contains(&format!(
        "version: {}",
        tuf::SIGSTORE_PRODUCTION_ROOT_VERSION
    )));
    assert!(text.contains(&format!("sha256: {}", tuf::SIGSTORE_PRODUCTION_ROOT_SHA256)));
    assert!(text.contains(&format!("source: {}", tuf::SIGSTORE_PRODUCTION_ROOT_SOURCE)));
    assert!(text.contains(&format!(
        "fetched_at: {}",
        tuf::SIGSTORE_PRODUCTION_ROOT_FETCHED_AT
    )));
}

/// Bug it catches: `expires` printed from somewhere other than the
/// asset itself (e.g. a stale constant), so an operator is told the root
/// is fine when it is not.
#[test]
fn test_tuf_root_show_expires_matches_the_bundled_asset() {
    let out = sign(&["tuf-root", "show"]);
    let expires = stdout(&out)
        .lines()
        .find_map(|l| l.strip_prefix("expires: ").map(str::to_owned))
        .expect("expires line");

    let asset = String::from_utf8_lossy(tuf::SIGSTORE_PRODUCTION_ROOT_BYTES);
    assert!(
        asset.contains(&format!("\"expires\": \"{expires}\"")),
        "`show` reported {expires}, which is not in the bundled root"
    );
}

// ---- verify: success -----------------------------------------------

#[test]
fn test_tuf_root_verify_bundled_root_exits_zero() {
    let out = sign(&["tuf-root", "verify"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(stdout(&out).starts_with("OK:"), "stdout: {}", stdout(&out));
}

/// Bug it catches: `--root` being parsed but ignored, so every path
/// "verifies" the bundled root. Proven by the paired tamper test below:
/// the SAME bytes pass here and fail there only if the file is read.
#[test]
fn test_tuf_root_verify_valid_custom_path_exits_zero() {
    let path = write_tmp("valid", tuf::SIGSTORE_PRODUCTION_ROOT_BYTES);
    let out = sign(&["tuf-root", "verify", "--root", path_str(&path)]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains(path_str(&path)),
        "output names the file checked"
    );
}

// ---- verify: distinct failures -------------------------------------

/// Bug it catches: an expired root reported as success or as a generic
/// failure; scripts need the distinct code to decide to wait for a
/// refresh.
#[test]
fn test_tuf_root_verify_expired_root_exits_four() {
    let path = write_tmp("expired", EXPIRED_ROOT);
    let out = sign(&["tuf-root", "verify", "--root", path_str(&path)]);
    assert_eq!(code(&out), 4, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("expired"), "stderr: {}", stderr(&out));
}

#[test]
fn test_tuf_root_verify_not_json_exits_three() {
    let path = write_tmp("garbage", b"this is not json");
    let out = sign(&["tuf-root", "verify", "--root", path_str(&path)]);
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
}

/// Valid JSON that is not a root envelope.
#[test]
fn test_tuf_root_verify_wrong_shape_exits_three() {
    let path = write_tmp("shape", br#"{"signed":{"_type":"targets"}}"#);
    let out = sign(&["tuf-root", "verify", "--root", path_str(&path)]);
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
}

/// Bug it catches: a verify that only parses and checks expiry. A root
/// whose contents were altered after signing must be rejected, and with
/// a code different from "expired" and "malformed".
#[test]
fn test_tuf_root_verify_tampered_root_exits_five() {
    let path = write_tmp("tampered", &tampered_bundled_root());
    let out = sign(&["tuf-root", "verify", "--root", path_str(&path)]);
    assert_eq!(code(&out), 5, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("below threshold"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn test_tuf_root_verify_missing_file_exits_one() {
    let out = sign(&[
        "tuf-root",
        "verify",
        "--root",
        "definitely/not/a/real/root.json",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("read "), "stderr: {}", stderr(&out));
}

// ---- usage ---------------------------------------------------------

/// Bug it catches: a malformed command line being accepted (e.g. `show`
/// with stray arguments silently ignored) or reported with a code that
/// collides with a root-health failure.
#[test]
fn test_tuf_root_bad_usage_exits_one() {
    let cases: [&[&str]; 5] = [
        &["tuf-root"],
        &["tuf-root", "bogus"],
        &["tuf-root", "show", "extra"],
        &["tuf-root", "verify", "--bad"],
        &["tuf-root", "verify", "--root"],
    ];
    for args in cases {
        let out = sign(args);
        assert_eq!(code(&out), 1, "args {args:?}; stderr: {}", stderr(&out));
        assert!(
            stdout(&out).is_empty(),
            "usage errors print nothing to stdout: {args:?}"
        );
    }
}

#[test]
fn test_tuf_root_failure_codes_do_not_collide() {
    let expired = code(&sign(&[
        "tuf-root",
        "verify",
        "--root",
        path_str(&write_tmp("c-expired", EXPIRED_ROOT)),
    ]));
    let malformed = code(&sign(&[
        "tuf-root",
        "verify",
        "--root",
        path_str(&write_tmp("c-garbage", b"x")),
    ]));
    let tampered = code(&sign(&[
        "tuf-root",
        "verify",
        "--root",
        path_str(&write_tmp("c-tampered", &tampered_bundled_root())),
    ]));
    assert_eq!([expired, malformed, tampered], [4, 3, 5]);
}
