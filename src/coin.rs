fn main() {
    let price = 3950;

    for i500 in 0..11 {
        for i100 in 0..4 {
            for i50 in 0..11 {
                let total = i500 * 500 + i100 * 100 + i50 * 50;
                if price == total {
                    println!("500 * {} + 100 * {} + 10 * {}", i500, i100, i50);
                }
            }
        }
    }
}
