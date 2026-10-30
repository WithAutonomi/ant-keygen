//! ML-DSA-65 key management utility for Autonomi release signing.
//!
//! This utility provides:
//! - Keypair generation for release signing
//! - Binary signing with ML-DSA-65
//! - Signature verification
//! - Checking that a secret key (e.g. a CI secret) matches the expected public key
//!
//! # Usage
//!
//! ```text
//! ant-keygen generate [output-dir]    Generate a new keypair
//! ant-keygen sign --key <key> --input <file> --output <sig>
//! ant-keygen verify --key <key> --input <file> --signature <sig>
//! ant-keygen verify-key --public-key <key.pub> [--hex <hex>]
//! ```
//!
//! Every command exits with code 0 on success and 1 on any failure.

use clap::{Parser, Subcommand};
use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process;

/// Default signing context for domain separation (prevents cross-protocol attacks).
const DEFAULT_SIGNING_CONTEXT: &str = "ant-node-release-v1";

/// ML-DSA-65 sizes (FIPS 204).
const SECRET_KEY_SIZE: usize = 4032;
const PUBLIC_KEY_SIZE: usize = 1952;

const SECRET_KEY_FILE: &str = "release-signing-key.secret";
const PUBLIC_KEY_FILE: &str = "release-signing-key.pub";
const EMBED_FILE: &str = "release_key_embed.rs";

/// Message signed by the self-checks in `generate` and `verify-key`.
const SELF_CHECK_MESSAGE: &[u8] = b"ant-keygen-key-validation-test";

#[derive(Parser)]
#[command(name = "ant-keygen")]
#[command(about = "ML-DSA-65 key management for Autonomi releases")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ML-DSA-65 keypair (refuses to overwrite existing key files)
    Generate {
        /// Output directory for keys
        #[arg(default_value = ".")]
        output_dir: PathBuf,
    },
    /// Sign a file with ML-DSA-65
    Sign {
        /// Path to the secret key file
        #[arg(short, long)]
        key: PathBuf,
        /// Path to the file to sign
        #[arg(short, long)]
        input: PathBuf,
        /// Path to write the signature
        #[arg(short, long)]
        output: PathBuf,
        /// Signing context for domain separation
        #[arg(short, long, default_value = DEFAULT_SIGNING_CONTEXT)]
        context: String,
    },
    /// Verify a signature
    Verify {
        /// Path to the public key file
        #[arg(short, long)]
        key: PathBuf,
        /// Path to the file that was signed
        #[arg(short, long)]
        input: PathBuf,
        /// Path to the signature file
        #[arg(short, long)]
        signature: PathBuf,
        /// Signing context for domain separation (must match the context used during signing)
        #[arg(long, default_value = DEFAULT_SIGNING_CONTEXT)]
        context: String,
    },
    /// Check that a hex-encoded secret key (e.g. a CI secret) matches the expected public key
    VerifyKey {
        /// Hex-encoded secret key string (reads from stdin if not provided)
        #[arg(short = 'x', long)]
        hex: Option<String>,
        /// Path to the public key the secret key must belong to
        #[arg(short = 'p', long)]
        public_key: PathBuf,
        /// Signing context used for the test signature
        #[arg(long, default_value = DEFAULT_SIGNING_CONTEXT)]
        context: String,
    },
}

/// Stack for the thread that runs the command. ML-DSA keeps large arrays on the stack,
/// and unoptimised builds overflow the 1 MiB main-thread stack Windows gives a process.
/// 8 MiB is what Linux gives the main thread.
const STACK_SIZE: usize = 8 * 1024 * 1024;

fn main() {
    let cli = Cli::parse();

    let result = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || run(cli.command))
        .map_err(|e| format!("failed to start the worker thread: {e}"))
        .and_then(|worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err("the worker thread panicked".to_string()))
        });

    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        process::exit(1);
    }
}

fn run(command: Commands) -> Result<(), String> {
    match command {
        Commands::Generate { output_dir } => generate_keypair(&output_dir),
        Commands::Sign {
            key,
            input,
            output,
            context,
        } => sign_file(&key, &input, &output, &context),
        Commands::Verify {
            key,
            input,
            signature,
            context,
        } => verify_signature(&key, &input, &signature, &context),
        Commands::VerifyKey {
            hex,
            public_key,
            context,
        } => verify_hex_key(hex, &public_key, &context),
    }
}

fn read_file(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("failed to read {what} {}: {e}", path.display()))
}

fn load_public_key(path: &Path) -> Result<MlDsaPublicKey, String> {
    let bytes = read_file(path, "public key")?;
    if bytes.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "public key {} is {} bytes, expected {PUBLIC_KEY_SIZE}",
            path.display(),
            bytes.len()
        ));
    }
    MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &bytes)
        .map_err(|e| format!("failed to parse public key {}: {e}", path.display()))
}

/// Signs [`SELF_CHECK_MESSAGE`] with `secret_key` and verifies it against `public_key`.
fn keys_match(
    secret_key: &MlDsaSecretKey,
    public_key: &MlDsaPublicKey,
    context: &str,
) -> Result<bool, String> {
    let dsa = ml_dsa_65();
    let signature = dsa
        .sign_with_context(secret_key, SELF_CHECK_MESSAGE, context.as_bytes())
        .map_err(|e| format!("signing failed: {e}"))?;
    dsa.verify_with_context(
        public_key,
        SELF_CHECK_MESSAGE,
        &signature,
        context.as_bytes(),
    )
    .map_err(|e| format!("verification failed: {e}"))
}

/// Creates `path` and writes `bytes` to it. Fails if the file already exists. With
/// `private`, the file is created readable and writable by the owner only (Unix).
fn write_new_file(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn generate_keypair(output_dir: &Path) -> Result<(), String> {
    println!("ML-DSA-65 Keypair Generator\n");

    let sk_path = output_dir.join(SECRET_KEY_FILE);
    let pk_path = output_dir.join(PUBLIC_KEY_FILE);
    let rust_code_path = output_dir.join(EMBED_FILE);

    // Never overwrite: replacing a release key by accident can't be undone.
    for path in [&sk_path, &pk_path, &rust_code_path] {
        if path.exists() {
            return Err(format!(
                "{} already exists; refusing to overwrite it. Move the existing keys away first.",
                path.display()
            ));
        }
    }

    fs::create_dir_all(output_dir).map_err(|e| {
        format!(
            "failed to create output directory {}: {e}",
            output_dir.display()
        )
    })?;

    println!("Generating ML-DSA-65 keypair...");

    let dsa = ml_dsa_65();
    let (public_key, secret_key) = dsa
        .generate_keypair()
        .map_err(|e| format!("failed to generate keypair: {e}"))?;

    if !keys_match(&secret_key, &public_key, DEFAULT_SIGNING_CONTEXT)? {
        return Err("the generated keypair failed its sign/verify self-check".to_string());
    }

    let pk_bytes = public_key.to_bytes();
    let sk_bytes = secret_key.to_bytes();

    println!("  Public key size: {} bytes", pk_bytes.len());
    println!("  Secret key size: {} bytes", sk_bytes.len());
    println!("  Sign/verify self-check passed.");

    // Save secret key to file (KEEP THIS SECURE!)
    write_new_file(&sk_path, &sk_bytes, true)?;
    println!("\nSecret key saved to: {}", sk_path.display());
    println!("  WARNING: Keep this file secure! It's needed for signing releases.");

    write_new_file(&pk_path, &pk_bytes, false)?;
    println!("Public key saved to: {}", pk_path.display());

    let key_array = rust_byte_array(&pk_bytes);
    let rust_code = format!(
        "/// Embedded release signing public key (ML-DSA-65).\n\
         ///\n\
         /// This key is used to verify signatures on released binaries.\n\
         /// The corresponding private key is held by authorized release signers.\n\
         /// Generated: {}\n\
         const RELEASE_SIGNING_KEY: &[u8] = &[\n{key_array}];\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    write_new_file(&rust_code_path, rust_code.as_bytes(), false)?;
    println!("Rust embed code saved to: {}", rust_code_path.display());

    // Also print to stdout for convenience
    println!("\n--- Rust code for embedding ---\n");
    println!("const RELEASE_SIGNING_KEY: &[u8] = &[\n{key_array}];");
    println!("\n--- End of Rust code ---");
    Ok(())
}

/// Formats bytes as the body of a Rust byte-array literal, 16 per line.
fn rust_byte_array(bytes: &[u8]) -> String {
    let mut out = String::new();
    for row in bytes.chunks(16) {
        let line: Vec<String> = row.iter().map(|b| format!("0x{b:02x},")).collect();
        let _ = writeln!(out, "    {}", line.join(" "));
    }
    out
}

fn sign_file(
    key_path: &Path,
    input_path: &Path,
    output_path: &Path,
    context: &str,
) -> Result<(), String> {
    println!("Signing {} with ML-DSA-65...", input_path.display());

    let sk_bytes = read_file(key_path, "secret key")?;
    let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .map_err(|e| format!("failed to parse secret key {}: {e}", key_path.display()))?;

    let data = read_file(input_path, "input file")?;

    let dsa = ml_dsa_65();
    let signature = dsa
        .sign_with_context(&secret_key, &data, context.as_bytes())
        .map_err(|e| format!("failed to create signature: {e}"))?;

    let sig_bytes = signature.to_bytes();
    fs::write(output_path, &sig_bytes)
        .map_err(|e| format!("failed to write signature {}: {e}", output_path.display()))?;

    println!("Signature written to: {}", output_path.display());
    println!("  Signature size: {} bytes", sig_bytes.len());
    println!("  Context: {context}");
    Ok(())
}

/// Decodes a hex string, ignoring whitespace (line breaks from copy-paste or `echo`).
/// Any other non-hex character is an error.
fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<(usize, char)> = input
        .char_indices()
        .filter(|(_, c)| !c.is_whitespace())
        .collect();
    if let Some((pos, c)) = digits.iter().find(|(_, c)| !c.is_ascii_hexdigit()) {
        return Err(format!("invalid hex character {c:?} at position {pos}"));
    }
    if digits.len() % 2 != 0 {
        return Err(format!(
            "hex string has an odd number of digits ({})",
            digits.len()
        ));
    }
    Ok(digits
        .chunks(2)
        .map(|pair| {
            let hi = pair[0].1.to_digit(16).unwrap_or(0);
            let lo = pair[1].1.to_digit(16).unwrap_or(0);
            // Both are hex digits (checked above), so this fits in a byte.
            (hi * 16 + lo) as u8
        })
        .collect())
}

fn verify_hex_key(
    hex_input: Option<String>,
    public_key_path: &Path,
    context: &str,
) -> Result<(), String> {
    println!("Checking hex-encoded ML-DSA-65 secret key...\n");

    let hex_str = match hex_input {
        Some(hex) => hex,
        None => {
            eprintln!("Reading hex from stdin...");
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                .map_err(|e| format!("failed to read from stdin: {e}"))?;
            buf
        }
    };

    let bytes = decode_hex(&hex_str)?;
    if bytes.len() != SECRET_KEY_SIZE {
        return Err(format!(
            "hex string decodes to {} bytes, expected {SECRET_KEY_SIZE}",
            bytes.len()
        ));
    }
    let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &bytes)
        .map_err(|e| format!("failed to parse secret key: {e}"))?;
    println!("  Secret key parses ({SECRET_KEY_SIZE} bytes).");

    let public_key = load_public_key(public_key_path)?;

    if !keys_match(&secret_key, &public_key, context)? {
        return Err(format!(
            "the secret key does not match the public key {}. A signature made with it \
             would not verify.",
            public_key_path.display()
        ));
    }
    println!(
        "  A test signature with context \"{context}\" verifies against {}.",
        public_key_path.display()
    );
    println!("\nKey is VALID: it matches the expected public key.");
    Ok(())
}

fn verify_signature(
    key_path: &Path,
    input_path: &Path,
    sig_path: &Path,
    context: &str,
) -> Result<(), String> {
    println!("Verifying signature for {}...", input_path.display());

    let public_key = load_public_key(key_path)?;
    let data = read_file(input_path, "input file")?;
    let sig_bytes = read_file(sig_path, "signature")?;
    let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| format!("failed to parse signature {}: {e}", sig_path.display()))?;

    let dsa = ml_dsa_65();
    match dsa.verify_with_context(&public_key, &data, &signature, context.as_bytes()) {
        Ok(true) => {
            println!("Signature is VALID");
            Ok(())
        }
        Ok(false) => Err("Signature is INVALID".to_string()),
        Err(e) => Err(format!("signature verification error: {e}")),
    }
}
