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
//! To achieve this, rcrypt compresses fields of the hash, in accordance with the
//! [BMCF specification](https://github.com/ademarre/binary-mcf).
//! After applying the compression algorithm implemented in this crate, the
//! 60 byte bcrypt hash is compressed into a 40 byte long binary hash, that
//! is returned as a [`Vec<u8>`].
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

/// Hash and salt the provided password with the given cost. If you don't know
/// which cost to use, use the [`DEFAULT_COST`]. The OS randomness is used to
/// generate the salt
pub fn hash<T: AsRef<[u8]>>(password: T, cost: u32) -> RcryptResult<Vec<u8>> {
    let bcrypt_hash = bcrypt::hash(password, cost)?;
    let compressed_hash = crate::algorithm::encode_into_bmcf(&bcrypt_hash)?;
    Ok(compressed_hash)
}

/// Hash and salt the provided password with the given cost and salt. If you don't know
/// which cost to use, use the [`DEFAULT_COST`]
pub fn hash_with_salt<T: AsRef<[u8]>>(
    password: T,
    cost: u32,
    salt: &[u8],
) -> RcryptResult<Vec<u8>> {
    let bcrypt_hash = bcrypt::hash_with_salt(password, cost, salt)?.to_string();
    let compressed_hash = crate::algorithm::encode_into_bmcf(&bcrypt_hash)?;
    Ok(compressed_hash)
}

/// Verify if the provided password is correct using the provided hash
pub fn verify<T: AsRef<[u8]>>(password: T, hash: &[u8]) -> RcryptResult<bool> {
    let decompressed_hash = crate::algorithm::decode_into_mcf(hash)?;
    let verified = bcrypt::verify(password, &decompressed_hash)?;
    Ok(verified)
}

pub mod bmcf {
    //! # MCF/BMCF tools
    //!
    //! This module contains the core algorithms used to compress/decompress hashes
    //! per the BMCF specification. It is made available if you want to use it
    //! externally.
    pub use crate::algorithm::decode_into_mcf;
    pub use crate::algorithm::encode_into_bmcf;
}

mod algorithm {
    use crate::{RcryptError, RcryptResult};

    const EXPECTED_PARTS: usize = 3;
    const RCRYPT_EXPECTED_SIZE: usize = 40;
    const BCRYPT_EXPECTED_SIZE: usize = 60;
    const BCRYPT_EXPECTED_SIZE_SALTDIGEST: usize = 53;
    const BCRYPT_EXPECTED_SIZE_FIELDS: usize = 2;

    /// Encode an MCF hash into BMCF. This is the core compression algorithm
    /// used by rcrypt
    pub fn encode_into_bmcf(input: &str) -> RcryptResult<Vec<u8>> {
        if input.len() != BCRYPT_EXPECTED_SIZE {
            return Err(RcryptError::WrongSize(BCRYPT_EXPECTED_SIZE, input.len()));
        }
        if input.as_bytes()[0] != b'$' {
            return Err(RcryptError::UnsupportedHashPrefix(input.as_bytes()[0]));
        }
        let mut buf: Vec<u8> = Vec::with_capacity(RCRYPT_EXPECTED_SIZE);
        let parts: Vec<&str> = input.split('$').filter(|s| !s.is_empty()).collect();
        if parts.len() != EXPECTED_PARTS {
            return Err(RcryptError::CorruptedHash(format!(
                "Expected 3 parts, found {}",
                parts.len()
            )));
        }
        match (parts[0].len(), parts[1].len(), parts[2].len()) {
            (
                BCRYPT_EXPECTED_SIZE_FIELDS,
                BCRYPT_EXPECTED_SIZE_FIELDS,
                BCRYPT_EXPECTED_SIZE_SALTDIGEST,
            ) => {}
            (p1l, p2l, p3l) => {
                return Err(RcryptError::CorruptedHash(format!(
                    "Expected 3 parts with lengths {}, {}, {}. Found lengths {}, {} and {} instead",
                    BCRYPT_EXPECTED_SIZE_FIELDS,
                    BCRYPT_EXPECTED_SIZE_FIELDS,
                    BCRYPT_EXPECTED_SIZE_SALTDIGEST,
                    p1l,
                    p2l,
                    p3l
                )))
            }
        }
        // the scheme (2x, 2y, ...)
        let scheme = parts[0];
        // the cost
        let cost: u8 = parts[1]
            .parse()
            .map_err(|_| RcryptError::BadCost(parts[1].to_owned()))?;
        // the salt (22-bytes)
        let salt = &parts[2][0..22];
        // the digest (31-bytes)
        let digest = &parts[2][22..];
        // decode salt
        let salt_d = base64::decode_config(&salt, base64::BCRYPT)?;
        // decode digest
        let digest_d = base64::decode_config(&digest, base64::BCRYPT)?;
        let mask = cost & 0x1F;
        match scheme {
            "2" => buf.push(0x20 | mask),
            "2a" => buf.push(0x40 | mask),
            "2x" => buf.push(0x60 | mask),
            "2y" => buf.push(0x80 | mask),
            "2b" => buf.push(0xA0 | mask),
            _ => return Err(RcryptError::UnknownScheme(scheme.to_owned())),
        };
        buf.extend(salt_d);
        buf.extend(digest_d);
        Ok(buf)
    }
    /// Decode a BMCF hash into MCF. This is the core decompression algorithm
    /// used by rcrypt
    pub fn decode_into_mcf(input: &[u8]) -> RcryptResult<String> {
        if input.len() != RCRYPT_EXPECTED_SIZE {
            return Err(RcryptError::WrongSize(RCRYPT_EXPECTED_SIZE, input.len()));
        }
        let mut st: Vec<u8> = Vec::with_capacity(BCRYPT_EXPECTED_SIZE);
        st.push(b'$');
        // get scheme
        let header_octet = input[0];
        let scheme_id = header_octet & 0xE0;
        match scheme_id {
            0x20 => st.push(b'2'),
            0x40 => st.extend(b"2a"),
            0x60 => st.extend(b"2x"),
            0x80 => st.extend(b"2y"),
            0xA0 => st.extend(b"2b"),
            _ => return Err(RcryptError::UnknownScheme(scheme_id.to_string())),
        };
        st.push(b'$');
        // get cost
        let costint = header_octet - scheme_id;
        if costint > 31 {
            return Err(RcryptError::BadCost(format!(
                "expected cost is 4-31, found {}",
                costint
            )));
        }
        // push cost
        st.push((costint / 10) + 48);
        st.push((costint % 10) + 48);
        st.push(b'$');
        // get salt
        let salt = base64::encode_config(&input[1..17], base64::BCRYPT);
        st.extend(salt.bytes());
        // get digest
        let digest = base64::encode_config(&input[17..], base64::BCRYPT);
        st.extend(digest.bytes());
        Ok(unsafe { String::from_utf8_unchecked(st) })
    }
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
        BadCost(String),
        /// Unknown scheme
        UnknownScheme(String),
        /// An error in the underlying bcrypt call
        BcryptError(bcrypt::BcryptError),
        /// An error while decoding base64 data
        Base64Error(base64::DecodeError),
    }

    impl From<base64::DecodeError> for RcryptError {
        fn from(e: base64::DecodeError) -> Self {
            Self::Base64Error(e)
        }
    }

    impl From<bcrypt::BcryptError> for RcryptError {
        fn from(e: bcrypt::BcryptError) -> Self {
            Self::BcryptError(e)
        }
    }

    impl fmt::Display for RcryptError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                RcryptError::BadCost(c) => write!(f, "failed to decode cost: {}", c),
                RcryptError::Base64Error(e) => write!(f, "base64 decode error: {}", e),
                RcryptError::BcryptError(e) => write!(f, "bcrypt error: {}", e),
                RcryptError::CorruptedHash(e) => write!(f, "corrupted hash: {}", e),
                RcryptError::UnknownScheme(e) => write!(f, "unknown scheme: {}", e),
                RcryptError::UnsupportedHashPrefix(p) => write!(f, "unsupported prefix: {}", p),
                RcryptError::WrongSize(esz, sz) => {
                    write!(f, "wrong hash size. expected {} bytes, found {}", esz, sz)
                }
            }
        }
    }
}
