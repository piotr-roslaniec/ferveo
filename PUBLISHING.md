# New version publishing instructions

We're [cargo-smart-release](https://lib.rs/crates/cargo-smart-release) to automate the release process.

## Writing commit messages

As long as you adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format, you can
write your commit messages however you want.

## Releasing workflow

We're currently not releasing Python and WASM bindings, we're only releasing the Rust crate.

In order to release a new version, simply run:

```bash
cargo smart-release --update-crates-index
```

Inspect the changes and confirm the release:

```bash
cargo smart-release --update-crates-index --execute
```

