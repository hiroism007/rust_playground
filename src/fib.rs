fn main() {
    let mut a = 1;
    let mut b = 1;

    for _ in 1..30 {
        println!("{}", a + b);

        let tmp = a;
        a = b;
        b = b + tmp;
    }
}
