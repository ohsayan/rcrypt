extern crate rcrypt;
use rcrypt::DEFAULT_COST;

#[test]
fn hash_and_verify() {
    let mypass = String::from("pass123");
    let hash: Vec<u8> = rcrypt::hash(&mypass, DEFAULT_COST).unwrap();
    assert!(rcrypt::verify(&mypass, &hash).unwrap());
}

#[test]
fn hash_and_verify_custom_salt() {
    let mypass = String::from("pass123");
    let hash: Vec<u8> = rcrypt::hash_with_salt(&mypass, DEFAULT_COST, b"abcdefgh12345678").unwrap();
    assert!(rcrypt::verify(&mypass, &hash).unwrap());
}
