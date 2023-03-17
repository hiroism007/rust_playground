mod playground;

#[allow(unused_imports)]
use playground::ecdh::ecdh_key_exchange;
#[allow(unused_imports)]
use playground::ecdsa_verify::verify_ecdsa;
use playground::fiat_shamir::fiat_shamir;

fn main() {
    // verify_ecdsa();
    // ecdh_key_exchange();
    fiat_shamir();
}
