use num_bigint::BigInt;

fn main() {
    success();
}

fn fail() {
    let base: u128 = 1234;
    let result = base.pow(5678);
    println!("{}", result);
}

fn success() {
    let base = BigInt::from(1234);
    let result = base.pow(5678);
    println!("{}", result);
}
