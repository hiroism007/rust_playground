fn main() {
    let r = 3..=15;

    println!("{}..{}", r.start(), r.end());

    for i in 0..=15 {
        println!("for loop {}", i);
    }
}
