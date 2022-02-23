extern crate rcrypt;
use rcrypt::DEFAULT_COST;

#[test]
fn hash_and_verify() {
    let mypass = String::from("pass123");
    let hash: Vec<u8> = rcrypt::hash(&mypass, DEFAULT_COST).unwrap();
    assert!(rcrypt::verify(&mypass, &hash).unwrap());
}
