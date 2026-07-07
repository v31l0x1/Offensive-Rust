use std::io;

fn main() {

    let mut n = String::new();
    println!("Enter count:");

    io::stdin().read_line(&mut n).expect("Failed to read line");
    // println!("Hello, {}!", n.trim());

    let count = n.trim().parse::<u32>().unwrap();

    let mut v1:Vec<i32> = Vec::new();

    for i in 0..count {
        let mut temp = String::new();
        io::stdin().read_line(&mut temp).expect("Failed to read line");
        println!("Line {}: {}", i + 1, temp.trim());

        v1.push(temp.trim().parse::<i32>().unwrap());
    }
}