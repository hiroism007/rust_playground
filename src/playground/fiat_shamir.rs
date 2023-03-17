use secp256k1::rand::rngs::OsRng;
use secp256k1::{generate_keypair, PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
pub fn fiat_shamir() {
    println!("---------------------start prover---------------------");
    let (pk, commitment, response) = do_as_prover();
    println!("-------------------start verifier---------------------");
    do_as_verifier(pk, commitment, response);
}

fn do_as_prover() -> (PublicKey, PublicKey, SecretKey) {
    // step 1: Prover Generates a keypair
    let (sk, pk) = gen_keypair();
    println!("prover sk: {:?}", sk.display_secret());
    println!("prover pk: {:?}", pk);

    // step 2: Prover generates a random secret and calculate the commitment A = r * G
    let (random_secret, commitment) = gen_keypair();
    println!("prover random_secret: {:?}", random_secret.display_secret());
    println!("prover commitment: {:?}", commitment);

    // step 3: Prover generate a challenge, challenge = H(p, commitment)
    let challenge = gen_hash(pk, commitment);
    println!("prover challenge: {:?}", challenge.display_secret());

    // step 4: Prover calculates the response, s = random_secret + (challenge * sk)
    let inv = challenge
        .mul_tweak(&Scalar::from(sk))
        .map(Scalar::from)
        .unwrap();
    let response = random_secret.add_tweak(&inv).unwrap();
    println!("prover response: {:?}", response.display_secret());

    // step 5: Prover sends public key, the commitment and response to the verifier
    println!("prover provides pk, commitment, response to the verifier");
    (pk, commitment, response)
}

fn do_as_verifier(pk: PublicKey, commitment: PublicKey, response: SecretKey) {
    // step 1: Verifier re compute challenge from pk and commitment
    let recomputed_challenge = gen_hash(pk, commitment);
    println!(
        "verifier recomputed_challenge: {:?}",
        recomputed_challenge.display_secret()
    );

    let secp = Secp256k1::new();
    // step 2: Verifier checks the response
    let sg = PublicKey::from_secret_key(&secp, &response);
    println!("verifier sg: {:?}", sg);

    // step 3: Verifier checks the commitment
    let cx = pk
        .mul_tweak(&secp, &Scalar::from(recomputed_challenge))
        .unwrap();
    println!("verifier cx: {:?}", cx);
    let commitment_plus_cx = commitment.combine(&cx).unwrap();
    println!("verifier commitment_plus_cx: {:?}", commitment_plus_cx);

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
