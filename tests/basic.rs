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

#[test]
fn hash_and_verify_cost_9() {
    let mypass = String::from("pass123");
    let hash: Vec<u8> = rcrypt::hash(&mypass, 9).unwrap();
    assert!(rcrypt::verify(&mypass, &hash).unwrap());
}

#[test]
fn hash_and_verify_72_char_long_pass() {
    let pass = "dadd75a296c46bbf56563ac1d4e408636bae7ee045c18311ec217f36896f88b77f3ac6ee";
    let hash = rcrypt::hash(pass, DEFAULT_COST).unwrap();
    assert!(rcrypt::verify(pass, &hash).unwrap());
}
