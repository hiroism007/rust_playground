fn main() {
    for i in 1..101 {
        if i % 3 == 0 && i % 5 == 0 {
            println!("fizzbuz {}", i)
        } else if i % 3 == 0 {
            println!("fizz")
        } else if i % 5 == 0 {
            println!("buzz")
        } else {
            println!("{}", i)
        }
    }
}
