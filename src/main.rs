mod playground;

use playground::ecdh::ecdh_key_exchange;
use playground::ecdsa_verify::verify_ecdsa;

fn main() {
    // verify_ecdsa();
    ecdh_key_exchange();
}
