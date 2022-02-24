/*
 * Copyright (c) 2022, Sayan Nandan <nandansayan@outlook.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//! # rcrypt: A compact hashing and salting library based on bcrypt with smaller hashes
//!
//! `rcrypt`, short for "reduced crypt" is a more compact alternative to bcrypt,
//! generating **hashes that are 33.3% smaller** (40 bytes vs 60 bytes) than bcrypt.
//!
//! To achieve this, rcrypt merges fields of the hash and encodes the salt+digest into binary,
//! in accordance with the [BMCF specification](https://github.com/ademarre/binary-mcf).
//! Read [more here](https://github.com/ohsayan/rcrypt#how-it-works).
//!
//! This is a very simple example that you can use for conveniently hashing and
//! salting passwords:
//! ```
//! let password = String::from("pass123");
//!	let hash = rcrypt::hash(&password, rcrypt::DEFAULT_COST).unwrap();
//!	assert!(rcrypt::verify(&password, &hash).unwrap());
//! ```
//!
//! ## Migrating from bcrypt
//!
//! To migrate from bcrypt, simply keep this in mind: the returned hash is a [`Vec<u8>`]
//! instead of a [`String`], since `rcrypt` returns hashes with binary data.
//! Similary, to verify a hash, you'll have to pass the password as usual but the hash
//! passed must be a `&[u8]`, corresponding to the binary hash that rcrypt generates.
//!
//! The rest remains unchanged.
//!

/// The default hash cost
pub const DEFAULT_COST: u32 = 12;
pub use crate::error::{RcryptError, RcryptResult};

mod algorithms;

/// Hash and salt the provided password with the given cost. If you don't know
/// which cost to use, use the [`DEFAULT_COST`]. The OS randomness is used to
/// generate the salt
pub fn hash<T: AsRef<[u8]>>(password: T, cost: u32) -> RcryptResult<Vec<u8>> {
    let hash = crate::algorithms::rcrypt_hash(password.as_ref(), cost)?;
    Ok(hash)
}

/// Hash and salt the provided password with the given cost and salt. If you don't know
/// which cost to use, use the [`DEFAULT_COST`]
pub fn hash_with_salt<T: AsRef<[u8]>>(
    password: T,
    cost: u32,
    salt: &[u8],
) -> RcryptResult<Vec<u8>> {
    let hash = crate::algorithms::rcrypt_hash_with(password.as_ref(), cost, salt)?;
    Ok(hash)
}

/// Verify if the provided password is correct using the provided hash
pub fn verify<T: AsRef<[u8]>>(password: T, hash: &[u8]) -> RcryptResult<bool> {
    let verified = crate::algorithms::rcrypt_verify(password.as_ref(), hash)?;
    Ok(verified)
}

pub mod bmcf {
    //! # MCF/BMCF tools
    //!
    //! This module contains encoding tools that enable you to conver bcrypt MCF
    //! hashes into their binary equivalent (BMCF) and decode binary hashes into
    //! MCF
    pub use crate::algorithms::decode_into_mcf;
    pub use crate::algorithms::encode_into_bmcf;
}

mod error {
    use std::fmt;
    /// A generic result for the rcrypt library
    pub type RcryptResult<T> = Result<T, RcryptError>;

    #[derive(Debug)]
    /// Errors that can result when hashing, salting, verifying, compressing
    /// or decompressing `rcrypt` hashes
    pub enum RcryptError {
        /// The hash is corrupted. The description is given in the tuple field
        CorruptedHash(String),
        /// The hash has the wrong size (expected, present)
        WrongSize(usize, usize),
        /// The hash prefix is unsupported
        UnsupportedHashPrefix(u8),
        /// The cost of the hash is incorrect
        BadDecodedCost(String),
        /// The cost is not allowed
        DisallowedCost(u32),
        /// Unknown scheme
        UnknownScheme(String),
        /// An error while decoding base64 data
        Base64Error(base64::DecodeError),
        /// The password contains illegal characters or is empty
        BadPassword,
        /// An error in the RNG call
        RngError(getrandom::Error),
        /// The salt size is invalid
        BadSalt(usize),
    }

    macro_rules! from {
        ($($ty:ty, $var:expr),*) => {
            $(impl From<$ty> for RcryptError {
                fn from(e: $ty) -> Self {
                    $var(e)
                }
            })*
        };
    }

    from!(
        base64::DecodeError,
        RcryptError::Base64Error,
        getrandom::Error,
        RcryptError::RngError
    );

    impl fmt::Display for RcryptError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                RcryptError::BadDecodedCost(c) => write!(f, "failed to decode cost: {}", c),
                RcryptError::Base64Error(e) => write!(f, "base64 decode error: {}", e),
                RcryptError::CorruptedHash(e) => write!(f, "corrupted hash: {}", e),
                RcryptError::UnknownScheme(e) => write!(f, "unknown scheme: {}", e),
                RcryptError::UnsupportedHashPrefix(p) => write!(f, "unsupported prefix: {}", p),
                RcryptError::WrongSize(esz, sz) => {
                    write!(f, "wrong hash size. expected {} bytes, found {}", esz, sz)
                }
                RcryptError::BadPassword => write!(f, "Bad password"),
                RcryptError::DisallowedCost(cst) => write!(f, "illegal cost: {}", cst),
                RcryptError::RngError(e) => write!(f, "error while generating salt: {}", e),
                RcryptError::BadSalt(slt) => write!(f, "Expected salt with 16 bytes. got {}", slt),
            }
        }
    }
}
