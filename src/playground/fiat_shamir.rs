use secp256k1::rand::rngs::OsRng;
use secp256k1::{generate_keypair, PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
pub fn fiat_shamir() {
    // step 1: Prover Generates a keypair
    let (sk, pk) = gen_keypair();

    // step 2: Prover generates a random r and calculate the commitment A = r * G
    let (random_secret, commitment) = gen_keypair();

    // step 3: Prover generate a challenge, c = H(p, commitment)
    let challenge = gen_hash(pk, commitment);

    // step 4: Prover calculates the response, s = r + challenge * sk
    let inv = challenge
        .mul_tweak(&Scalar::from(sk))
        .map(Scalar::from)
        .unwrap();
    let response = random_secret.add_tweak(&inv).unwrap();

    // step 5: Verifier re compute challenge from pubkey and commitment
    let recomputed_challenge = gen_hash(pk, commitment);

    let secp = Secp256k1::new();
    // step 6: Verifier checks the response
    let sg = PublicKey::from_secret_key(&secp, &response);

    let cx = pk
        .mul_tweak(&secp, &Scalar::from(recomputed_challenge))
        .unwrap();

    let commitment_plus_cx = commitment.combine(&cx).unwrap();

    assert_eq!(sg, commitment_plus_cx);
    println!("OK");
}

fn gen_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    generate_keypair(&mut OsRng)
}

fn gen_hash(pk: PublicKey, commitment: PublicKey) -> SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(pk.serialize());
    hasher.update(commitment.serialize());
    let hash = hasher.finalize();
    SecretKey::from_slice(&hash).unwrap()
}
