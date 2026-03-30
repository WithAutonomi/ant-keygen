# ant-keygen

ML-DSA-65 (FIPS 204) key management utility for Autonomi release signing. Provides post-quantum
cryptographic signing and verification of release binaries.

## Installation

Download the latest binary for your platform from
[GitHub Releases](https://github.com/WithAutonomi/ant-keygen/releases).

Or build from source:

```bash
cargo install --git https://github.com/WithAutonomi/ant-keygen
```

## Commands

### Generate a keypair

```bash
ant-keygen generate [output-dir]
```

Generates a new ML-DSA-65 keypair and outputs:
- `release-signing-key.secret` -- secret key (4032 bytes). **Keep this secure.**
- `release-signing-key.pub` -- public key (1952 bytes)
- `release_key_embed.rs` -- Rust code for embedding the public key in a binary

### Sign a file

```bash
ant-keygen sign --key <secret-key> --input <file> --output <signature>
```

Signs a file with ML-DSA-65 using domain-separated signing context. Produces a 3309-byte
signature file.

Options:
- `--context <string>` -- signing context for domain separation (default: `ant-node-release-v1`)

### Verify a signature

```bash
ant-keygen verify --key <public-key> --input <file> --signature <sig-file>
```

Verifies that a signature matches the file and public key. Exits with code 0 on success, 1 on
failure.

Options:
- `--context <string>` -- must match the context used during signing (default: `ant-node-release-v1`)

### Validate a hex-encoded key

```bash
ant-keygen verify-key --hex <hex-string>
# or pipe from stdin:
echo "$SECRET_KEY_HEX" | ant-keygen verify-key
```

Validates that a hex-encoded secret key is parseable and functional by performing a test signature.
Useful for verifying CI secrets are correctly configured.

Options:
- `--context <string>` -- signing context for the test signature (default: `ant-node-release-v1`)

## Signing context

All signing operations use a context string for domain separation, which prevents signatures from
being reused across different protocols. The default context is `ant-node-release-v1`. Use the
`--context` flag to specify a different context for other release processes.

The same context must be used for both signing and verification.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
