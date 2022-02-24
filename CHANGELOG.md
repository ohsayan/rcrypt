# Changelog

All changes made to this project will be noted in this file.

### 0.4.0

- `rcrypt::hash` now directly produces hashes instead of encoding into base64 and back
- (BREAKING): `RcryptError::BcryptError` was removed
- (BREAKING): `RcryptError::BadCost` is now `BadDecodedCost`
- New variants in `RcryptError`: `DisallowedCost`, `BadPassword`, `RngError` and `BadSalt`
- `rcrypt` now uses its own `bcrypt` implementation

## 0.3.0

- Fixed panic when a corrupted hash is passed to `rcrypt::verify`
- (BREAKING): `RcryptError::WrongSize` now has two `usize` tuple fields: one with expected has
  size, and the other with
- (BREAKING): `RcryptError::UnsupportedHash` is now `UnsupportedHashPrefix`

## 0.2.0

- Added `hash_with_salt` for adding custom salts

## 0.1.1

Fixed documentation incosistencies

## 0.1.0

Initial release
