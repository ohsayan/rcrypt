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

use super::{RcryptError, RcryptResult};
use blowfish::Blowfish;

const EXPECTED_PARTS: usize = 3;
const RCRYPT_BMCF_EXPECTED_SIZE: usize = 40;
const BCRYPT_EXPECTED_SIZE: usize = 60;
const BCRYPT_EXPECTED_SIZE_SALTDIGEST: usize = 53;
const BCRYPT_EXPECTED_SIZE_FIELDS: usize = 2;
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;

type Digest = [u8; 24];
type Salt = [u8; 16];

/// Encode an MCF hash into BMCF
pub fn encode_into_bmcf(input: &str) -> RcryptResult<Vec<u8>> {
    if input.len() != BCRYPT_EXPECTED_SIZE {
        return Err(RcryptError::WrongSize(BCRYPT_EXPECTED_SIZE, input.len()));
    }
    if input.as_bytes()[0] != b'$' {
        return Err(RcryptError::UnsupportedHashPrefix(input.as_bytes()[0]));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(RCRYPT_BMCF_EXPECTED_SIZE);
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
        .map_err(|_| RcryptError::BadDecodedCost(parts[1].to_owned()))?;
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
/// Decode a BMCF hash into MCF
pub fn decode_into_mcf(input: &[u8]) -> RcryptResult<String> {
    if input.len() != RCRYPT_BMCF_EXPECTED_SIZE {
        return Err(RcryptError::WrongSize(
            RCRYPT_BMCF_EXPECTED_SIZE,
            input.len(),
        ));
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
        return Err(RcryptError::BadDecodedCost(format!(
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

/// Generate a 16-byte salt
fn gensalt() -> Result<Salt, getrandom::Error> {
    let mut s = [0u8; 16];
    getrandom::getrandom(&mut s).map(|_| s)
}

/// Generate the digest from using the given password, salt and cost. This does the actual
/// thing
fn rcrypt_genhash(password: &[u8], cost: u32, salt: &[u8]) -> RcryptResult<Digest> {
    // check costs
    if cost > MAX_COST || cost < MIN_COST {
        return Err(RcryptError::DisallowedCost(cost));
    }
    // chck salt length
    if salt.len() != 16 {
        return Err(RcryptError::BadSalt(salt.len()));
    }
    // check if string has null
    if password.contains(&0) || password.is_empty() {
        return Err(RcryptError::BadPassword);
    }
    // truncate the password if > 72 to 71, because we need to also add the NULL terminator
    // due to a bug with C bcrypt impls (see: https://go-review.googlesource.com/c/crypto/+/177818)
    let trunc_password = if password.len() > 72 {
        &password[..71]
    } else {
        &password
    };
    // generate the null terminated password
    let mut null_terminated_password = Vec::with_capacity(password.len() + 1);
    null_terminated_password.extend(trunc_password);
    null_terminated_password.push(0);
    // this is the output digest
    let mut digest = [0u8; 24];
    // set up blowfish
    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(&salt, &null_terminated_password);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(&null_terminated_password);
        state.bc_expand_key(&salt);
    }
    // now rounds
    // Magic IV for 64 Blowfish encryptions
    // The string is "OrpheanBeholderScryDoubt" on big-endian. (== OpenBSD :D)
    let mut magic_cipher = [
        0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274,
    ];
    for i in 0..3 {
        let i: usize = i * 2;
        for _ in 0..64 {
            let [l, r] = state.bc_encrypt([magic_cipher[i], magic_cipher[i + 1]]);
            magic_cipher[i] = l;
            magic_cipher[i + 1] = r;
        }
        let buf = magic_cipher[i].to_be_bytes();
        digest[i * 4..][..4].copy_from_slice(&buf);
        let buf = magic_cipher[i + 1].to_be_bytes();
        digest[(i + 1) * 4..][..4].copy_from_slice(&buf);
    }
    Ok(digest)
}

/// This uses the digest produced by rcrypt_genhash, producing a BMCF encoded rcrypt hash
pub fn rcrypt_hash_with(password: &[u8], cost: u32, salt: &[u8]) -> RcryptResult<Vec<u8>> {
    // get the digest
    let digest = self::rcrypt_genhash(password.as_ref(), cost, &salt)?;
    let mut buf = Vec::with_capacity(RCRYPT_BMCF_EXPECTED_SIZE);
    // we generate a 2b scheme hash
    let mask = (cost as u8) & 0x1F;
    buf.push(0xA0 | mask);
    buf.extend(salt);
    // DON'T FORGET TO IGNORE THE LAST BYTE!
    buf.extend(&digest[..23]);
    Ok(buf)
}

/// Generates an rcrypt hash using a random salt
pub fn rcrypt_hash(password: &[u8], cost: u32) -> RcryptResult<Vec<u8>> {
    self::rcrypt_hash_with(password, cost, &self::gensalt()?)
}

/// Verifies an rcrypt hash against the provided input password
pub fn rcrypt_verify(password: &[u8], hash: &[u8]) -> RcryptResult<bool> {
    if hash.len() != RCRYPT_BMCF_EXPECTED_SIZE {
        return Err(RcryptError::WrongSize(
            RCRYPT_BMCF_EXPECTED_SIZE,
            hash.len(),
        ));
    }
    // get this hash's fields
    // the salt
    let salt = &hash[1..17];
    // the digest
    let digest = &hash[17..];
    // the header octet (merged)
    let header_octet = hash[0];
    // the scheme id using the mask
    let scheme_id = header_octet & 0xE0;
    match scheme_id {
        0x20 | 0x40 | 0x60 | 0x80 | 0xA0 => {}
        _ => {
            return Err(RcryptError::UnknownScheme(format!(
                "Expected valid rcrypt scheme ID, got {}",
                scheme_id
            )))
        }
    }
    // the cost
    let costint = header_octet - scheme_id;
    if (costint as u32) > MAX_COST || (costint as u32) < MIN_COST {
        return Err(RcryptError::BadDecodedCost(format!(
            "Expected cost in {min}-{max}, got {cost}",
            min = MIN_COST,
            max = MAX_COST,
            cost = costint
        )));
    }
    // now find the hash for this password
    let this_digest = self::rcrypt_genhash(password, costint as u32, salt)?;
    // check difference
    let mut delta = 0;
    for (a, b) in digest.into_iter().zip(this_digest) {
        delta |= a ^ b;
    }
    Ok(delta == 0)
}
