# `rcrypt`: A compact hashing and salting library

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/ohsayan/rcrypt/Test?label=tests&logo=rust&style=flat-square) [![Crates.io](https://img.shields.io/crates/v/rcrypt?style=flat-square)](https://crates.io/crates/rcrypt) [![docs.rs](https://img.shields.io/docsrs/rcrypt?style=flat-square)](https://docs.rs/rcrypt) [![Crates.io](https://img.shields.io/crates/l/rcrypt?style=flat-square)](./LICENSE)

`rcrypt`, short for "reduced crypt" is a compact hashing and salting library based on bcrypt **generating hashes that are 33.3% smaller than bcrypt** (40 bytes over 60 bytes).

It was originally made for a part of [Skytable](https://github.com/skytable/skytable)'s authentication
system storage, but was moved into a separate library for usage in the wider Rust community.
`rcrypt` is almost a drop-in replacement for the `bcrypt` crate. [Here's how it works](#how-it-works).

## Usage

```rust
use rcrypt::DEFAULT_COST;
// your password
let mypass = String::from("pass123");
// hash
let hash = rcrypt::hash(&mypass, DEFAULT_COST).unwrap();
// verify
assert!(rcrypt::verify(&mypass, &hash).unwrap());
```

The usage remains just the same for users who use the [bcrypt](https://crates.io/crates/bcrypt) crate, except that the `hash` method returns a `Vec<u8>` instead of a `String`, while for the `verify` method you need to pass a `&[u8]` for the hash.

## How it works

The smaller hash sizes result by `rcrypt` producing binary hashes and merging hash fields, in accordance
with the [BMCF spec](https://github.com/ademarre/binary-mcf).

- The field separators in the MCF hash are not present in hashes generated by `rcrypt`
- The cost and scheme fields are merged into one field
- The hashes generated by rcrypt do not use base64 which results in lesser bytes being used to store the
  salt+digest

## Acknowledgements

- The [Binary Modular Crypt Format specification](https://github.com/ademarre/binary-mcf) by [Andre DeMarre](https://github.com/ademarre)
- The [original bcrypt implementation in Rust](https://github.com/Keats/rust-bcrypt) by [Vincent Prouillet](https://github.com/Keats). The underlying
  bcrypt implementation used in this crate, and the public API are heavily inspired by the
  [`bcrypt`](https://crates.io/crates/bcrypt) crate

## License

This crate is distributed under the [Apache-2.0 License](./LICENSE).
