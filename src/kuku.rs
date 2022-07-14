fn main() {
    normal();
    another();
}

fn normal() {
    for y in 1..10 {
        for x in 1..10 {
            print!("{:3}", x * y);
        }
        println!("");
    }
}

fn another() {
    for y in 1..10 {
        let s = (1..10)
            .map(|x| format!("{:3}", x * y))
            .collect::<Vec<String>>()
            .join(",");
        println!("{}", s);
    }
}
