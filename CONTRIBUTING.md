# Contributing

## Development setup

Install Rust 1.85 or newer and the Protocol Buffer compiler.

Run the release checks before opening a pull request:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo package --locked
```

Keep public APIs documented with concise `///` comments and include tests for
behavior changes.

## Pull requests

Use a focused branch and explain the user-facing impact. Pull requests must
pass the CI workflow before merge.
