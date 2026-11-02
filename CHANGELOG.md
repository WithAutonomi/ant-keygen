# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Breaking

- **`verify-key` now requires `--public-key <file>`** and checks the secret key against it: it signs
  a test message and verifies the signature with that public key. Before, it only checked that the
  key parsed and could sign, so any well-formed ML-DSA-65 key printed "Key is VALID", including the
  wrong one. Non-hex characters in the input are now an error instead of being silently dropped.

### Fixes

- **`generate`** refuses to overwrite an existing `release-signing-key.secret`,
  `release-signing-key.pub` or `release_key_embed.rs`, writes the secret key with mode 0600 on
  Unix, and checks the new pair with a sign/verify round trip before writing it. The three files
  are written all or nothing: if one fails, the ones already written are removed again.
- Malformed keys, signatures or missing files now print an error and exit with code 1 instead of
  panicking. An unexpected panic exits with 101, so it can't pass for a handled error.
- Unoptimised builds no longer overflow the stack on Windows.

### CI

- New PR workflow: fmt, clippy and the new end-to-end tests (`tests/cli.rs`) on Linux, plus the
  tests on Windows.
- Releases check that the tag matches the Cargo.toml version, and pin `cross` to a fixed revision.

## [0.1.0] - 2026-03-30

Initial release. Extracted from [WithAutonomi/ant-node](https://github.com/WithAutonomi/ant-node)
as a standalone tool.

### Features

- **`generate`** -- Generate ML-DSA-65 (FIPS 204) keypairs for release signing. Outputs binary key
  files and Rust code for embedding the public key.
- **`sign`** -- Sign files with ML-DSA-65 using domain-separated signing context. Produces 3309-byte
  post-quantum signatures.
- **`verify`** -- Verify ML-DSA-65 signatures against a public key. Exits with code 0 on success,
  1 on failure.
- **`verify-key`** -- Validate hex-encoded secret keys (useful for CI secret verification). Accepts
  input via `--hex` flag or stdin.
- **`--context` flag** -- Configurable signing context for domain separation on `sign`, `verify`,
  and `verify-key` commands. Defaults to `ant-node-release-v1` for backwards compatibility.
- **Cross-platform release builds** -- GitHub Actions workflow producing archives for Linux x64,
  Linux ARM64, macOS x64, macOS ARM64, and Windows x64.
