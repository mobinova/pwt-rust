# AGENTS Guidelines for Coding Agents

These instructions apply to the entire repository.

## Rust code
- Format Rust files with `cargo fmt` before committing.
- Run `cargo test` after modifying any `.rs` files.
- Keep public APIs documented with concise `///` comments.

## Documentation
- Keep Markdown lines under 100 characters when possible.
- Use `#` headings for top-level sections.

## Pull Requests
- Summarize changes referencing the files touched.
- Include the result of `cargo test` in the testing section, or note if tests could not run.
