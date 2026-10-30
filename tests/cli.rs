//! End-to-end tests of the ant-keygen binary: every failure must exit with code 1 (not a
//! panic, not success), and every success with code 0.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_ant-keygen");
const SECRET: &str = "release-signing-key.secret";
const PUBLIC: &str = "release-signing-key.pub";

/// A fresh, empty directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("ant-keygen-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn run_with_stdin(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process was killed by a signal")
}

fn assert_ok(output: &Output, what: &str) {
    assert_eq!(
        code(output),
        0,
        "{what} should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_fails(output: &Output, what: &str) {
    assert_eq!(
        code(output),
        1,
        "{what} should fail with exit code 1\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn generate(dir: &Path) {
    assert_ok(&run(&["generate", p(dir)]), "generate");
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign(dir: &TempDir, key: &Path, input: &Path, context: Option<&str>) -> PathBuf {
    let sig = dir.path("file.sig");
    let mut args = vec![
        "sign",
        "--key",
        p(key),
        "--input",
        p(input),
        "--output",
        p(&sig),
    ];
    if let Some(context) = context {
        args.extend(["--context", context]);
    }
    assert_ok(&run(&args), "sign");
    sig
}

fn verify(key: &Path, input: &Path, sig: &Path, context: Option<&str>) -> Output {
    let mut args = vec![
        "verify",
        "--key",
        p(key),
        "--input",
        p(input),
        "--signature",
        p(sig),
    ];
    if let Some(context) = context {
        args.extend(["--context", context]);
    }
    run(&args)
}

#[test]
fn generate_writes_a_matching_keypair() {
    let dir = TempDir::new();
    generate(&dir.0);
    assert_eq!(fs::read(dir.path(SECRET)).unwrap().len(), 4032);
    assert_eq!(fs::read(dir.path(PUBLIC)).unwrap().len(), 1952);
    let embed = fs::read_to_string(dir.path("release_key_embed.rs")).unwrap();
    assert!(embed.contains("const RELEASE_SIGNING_KEY: &[u8] = &["));
    // 1952 bytes, one `0x..,` each.
    assert_eq!(embed.matches("0x").count(), 1952);
}

#[cfg(unix)]
#[test]
fn generate_writes_the_secret_key_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    generate(&dir.0);
    let mode = fs::metadata(dir.path(SECRET)).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "secret key mode is {:o}", mode & 0o777);
}

#[test]
fn generate_refuses_to_overwrite_existing_keys() {
    let dir = TempDir::new();
    generate(&dir.0);
    let secret = fs::read(dir.path(SECRET)).unwrap();
    let public = fs::read(dir.path(PUBLIC)).unwrap();

    assert_fails(&run(&["generate", p(&dir.0)]), "second generate");
    assert_eq!(
        fs::read(dir.path(SECRET)).unwrap(),
        secret,
        "secret key changed"
    );
    assert_eq!(
        fs::read(dir.path(PUBLIC)).unwrap(),
        public,
        "public key changed"
    );

    // Any one of the three files is enough to refuse.
    let other = TempDir::new();
    fs::write(other.path("release_key_embed.rs"), b"keep me").unwrap();
    assert_fails(
        &run(&["generate", p(&other.0)]),
        "generate over an embed file",
    );
    assert!(!other.path(SECRET).exists());
}

#[test]
fn sign_then_verify_round_trips() {
    let dir = TempDir::new();
    generate(&dir.0);
    let input = dir.path("file.bin");
    fs::write(&input, b"release binary contents").unwrap();

    let sig = sign(&dir, &dir.path(SECRET), &input, None);
    assert_eq!(fs::read(&sig).unwrap().len(), 3309);
    assert_ok(&verify(&dir.path(PUBLIC), &input, &sig, None), "verify");

    let sig = sign(&dir, &dir.path(SECRET), &input, Some("ant-release-v1"));
    assert_ok(
        &verify(&dir.path(PUBLIC), &input, &sig, Some("ant-release-v1")),
        "verify with a custom context",
    );
}

#[test]
fn verify_rejects_tampering() {
    let dir = TempDir::new();
    generate(&dir.0);
    let input = dir.path("file.bin");
    fs::write(&input, b"release binary contents").unwrap();
    let sig = sign(&dir, &dir.path(SECRET), &input, None);
    let public = dir.path(PUBLIC);

    // One byte of the signed file changed.
    let tampered = dir.path("tampered.bin");
    fs::write(&tampered, b"release binary contentS").unwrap();
    assert_fails(&verify(&public, &tampered, &sig, None), "tampered file");

    // One bit of the signature flipped.
    let mut sig_bytes = fs::read(&sig).unwrap();
    sig_bytes[100] ^= 0x01;
    let bad_sig = dir.path("bad.sig");
    fs::write(&bad_sig, &sig_bytes).unwrap();
    assert_fails(
        &verify(&public, &input, &bad_sig, None),
        "flipped signature",
    );

    // Signed with the default context, verified with another.
    assert_fails(
        &verify(&public, &input, &sig, Some("ant-release-v1")),
        "wrong context",
    );

    // A different keypair's public key.
    let other = TempDir::new();
    generate(&other.0);
    assert_fails(
        &verify(&other.path(PUBLIC), &input, &sig, None),
        "wrong public key",
    );
}

#[test]
fn verify_reports_malformed_inputs_without_panicking() {
    let dir = TempDir::new();
    generate(&dir.0);
    let input = dir.path("file.bin");
    fs::write(&input, b"data").unwrap();
    let sig = sign(&dir, &dir.path(SECRET), &input, None);

    let short_sig = dir.path("short.sig");
    fs::write(&short_sig, &fs::read(&sig).unwrap()[..100]).unwrap();
    assert_fails(
        &verify(&dir.path(PUBLIC), &input, &short_sig, None),
        "truncated signature",
    );

    let short_key = dir.path("short.pub");
    fs::write(&short_key, &fs::read(dir.path(PUBLIC)).unwrap()[..100]).unwrap();
    assert_fails(
        &verify(&short_key, &input, &sig, None),
        "truncated public key",
    );

    assert_fails(
        &verify(&dir.path("missing.pub"), &input, &sig, None),
        "missing public key",
    );
    assert_fails(
        &run(&[
            "sign",
            "--key",
            p(&short_key),
            "--input",
            p(&input),
            "--output",
            p(&dir.path("x.sig")),
        ]),
        "sign with a malformed secret key",
    );
}

#[test]
fn verify_key_accepts_the_matching_secret_key() {
    let dir = TempDir::new();
    generate(&dir.0);
    let hex = to_hex(&fs::read(dir.path(SECRET)).unwrap());
    let public = dir.path(PUBLIC);

    assert_ok(
        &run(&["verify-key", "--public-key", p(&public), "--hex", &hex]),
        "verify-key --hex",
    );

    // From stdin, with the line breaks and trailing newline a CI secret often has.
    let wrapped: String = hex
        .as_bytes()
        .chunks(64)
        .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
        .collect();
    assert_ok(
        &run_with_stdin(&["verify-key", "--public-key", p(&public)], &wrapped),
        "verify-key from stdin",
    );
}

#[test]
fn verify_key_rejects_a_valid_key_for_the_wrong_public_key() {
    let dir = TempDir::new();
    generate(&dir.0);
    let other = TempDir::new();
    generate(&other.0);
    let hex = to_hex(&fs::read(dir.path(SECRET)).unwrap());

    // A perfectly well-formed ML-DSA-65 secret key, but not the one for this public key.
    assert_fails(
        &run(&[
            "verify-key",
            "--public-key",
            p(&other.path(PUBLIC)),
            "--hex",
            &hex,
        ]),
        "verify-key with another keypair's public key",
    );
}

#[test]
fn verify_key_rejects_malformed_hex() {
    let dir = TempDir::new();
    generate(&dir.0);
    let hex = to_hex(&fs::read(dir.path(SECRET)).unwrap());
    let public = dir.path(PUBLIC);
    let check = |input: &str, what: &str| {
        assert_fails(
            &run(&["verify-key", "--public-key", p(&public), "--hex", input]),
            what,
        );
    };

    // Non-hex characters are errors, not silently dropped.
    check(
        &format!("{}zz{}", &hex[..100], &hex[100..]),
        "junk in the middle",
    );
    check(&format!("0x{hex}"), "0x prefix");
    check(&hex[..hex.len() - 2], "one byte short");
    check(&format!("{hex}00"), "one byte long");
    check(&hex[..hex.len() - 1], "odd number of digits");
    check("", "empty");
}

#[test]
fn verify_key_requires_a_public_key() {
    let output = run(&["verify-key", "--hex", "00"]);
    // clap's usage error.
    assert_eq!(code(&output), 2);
}
