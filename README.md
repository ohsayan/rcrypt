# `rcrypt`: A compact hashing and salting library

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/ohsayan/rcrypt/Test?label=tests&logo=rust&style=flat-square) [![Crates.io](https://img.shields.io/crates/v/rcrypt?style=flat-square)](https://crates.io/crates/rcrypt) [![docs.rs](https://img.shields.io/docsrs/rcrypt?style=flat-square)](https://docs.rs/rcrypt) [![Crates.io](https://img.shields.io/crates/l/rcrypt?style=flat-square)](./LICENSE)

`rcrypt`, short for "reduced crypt" is a compact hashing and salting library based on bcrypt **generating hashes that are 33.3% smaller than bcrypt** (40 bytes over 60 bytes).

It was originally made for a part of [Skytable](https://github.com/skytable/skytable)'s authentication
system storage, but was moved into a separate library for usage in the wider Rust community.
`rcrypt` is almost a drop-in replacement for the `bcrypt` crate.

The smaller hash sizes are achieved by rcrypt's
implementation of a segment compression/decompression algorithm, that compresses fields of the MCF hash
based on the [BMCF spec](https://github.com/ademarre/binary-mcf). The hashes produced are binary hashes.

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

## License

This crate is distributed under the [Apache-2.0 License](./LICENSE).
