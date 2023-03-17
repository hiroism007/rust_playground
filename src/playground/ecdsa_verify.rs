use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

#[allow(dead_code)]
pub fn verify_ecdsa() {
    let public_key = hex::decode("04432d675246b45c0bfa1dbc26235614e3e6b393aed6c161c81af3245ce5da425cada512ff09b6d117dc8c14affbc22a16024e2f75c41231336cacb17b7a65498b").unwrap();
    let verify_key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();

    let message = b"a44";
    let raw_der_sig = hex::decode("304502210086827ec2d5c4cafa09a84dc2becc584a6f42fcb9d1fae71afafae8f488904902022014ee30f9d6c28870e6e8c1663a4203ffbdb7c37808a2efce7d5051637890b418").unwrap();

    let signature = Signature::from_der(&raw_der_sig).unwrap();

    let res = verify_key.verify(message, &signature).is_ok();

    println!("res: {:?}", res);
}
