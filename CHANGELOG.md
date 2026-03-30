# Changelog

All notable changes to this project will be documented in this file.

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
