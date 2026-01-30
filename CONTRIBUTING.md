# Contributing to curl-rest

Thanks for your interest in contributing! This guide covers how to set up the project, run tests, and submit changes.

## Prerequisites

- Rust 1.85+ (see `rust-version` in `Cargo.toml`)
- A libcurl development package available on your system
  - If you prefer a vendored/static build, enable the appropriate `curl`/`curl-sys` features in your app so Cargo propagates them to this crate.

## Getting started

```sh
# build
cargo build

# run tests
cargo test

# run examples
cargo run --example curl -- GET https://example.com
TOKEN=secret cargo run --example headers -- https://example.com/private
```

## Benchmarks

```sh
cargo bench
```

## Feature flags

This crate exposes convenience features (default is `ssl`):

- `ssl`: OpenSSL-backed TLS (libcurl default)
- `rustls`: Rustls-backed TLS (disable default features in your dependency to avoid OpenSSL)
- `static-curl`: bundled libcurl
- `static-ssl`: bundled OpenSSL
- `vendored`: enables `static-curl` + `static-ssl`

## Coding guidelines

- Keep public API changes well documented (doc comments + README updates if behavior changes).
- Add or update tests for all new features and behavioral changes.
- Prefer small, focused commits and PRs.
- Use Conventional Commits for commit messages (e.g., `feat:`, `fix:`, `docs:`).

## Submitting changes

1. Fork and create a feature branch.
2. Make your change with tests/docs as needed.
3. Open a PR with a clear description and rationale.

## Reporting issues

Please include:

- Reproduction steps or a minimal example
- Expected vs actual behavior
- Rust version and OS
- Feature flags used (if relevant)

---

Questions or ideas? Open an issue or PR on GitHub.
