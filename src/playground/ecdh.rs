use k256::ecdh::EphemeralSecret;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{EncodedPoint, PublicKey};
use rand_core::OsRng; // requires 'getrandom' feature

#[allow(dead_code)]
pub fn ecdh_key_exchange() {
    // Alice の秘密鍵、公開鍵を作成
    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let alice_pk_bytes = EncodedPoint::from(alice_secret.public_key());
    let alice_public = PublicKey::from_sec1_bytes(alice_pk_bytes.as_ref())
        .expect("alice's public key is invalid!");

    println!(
        "alice_public: {:?}",
        hex::encode(alice_public.to_encoded_point(false).as_bytes())
    );

    // Bob の秘密鍵、公開鍵を作成
    let bob_secret = EphemeralSecret::random(&mut OsRng);
    let bob_pk_bytes = EncodedPoint::from(bob_secret.public_key());
    let bob_public =
        PublicKey::from_sec1_bytes(bob_pk_bytes.as_ref()).expect("bob's public key is invalid!");

    println!(
        "bob_public: {:?}",
        hex::encode(alice_public.to_encoded_point(false).as_bytes())
    );

    // それぞれ、自身の秘密鍵と相手の公開鍵を利用し、shared secret を作成
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // 両者が作成した shared secret が一致するか確認
    assert_eq!(
        alice_shared.raw_secret_bytes(),
        bob_shared.raw_secret_bytes()
    );
}
