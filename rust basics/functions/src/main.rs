
// fn print_line(phrase: &str) {
//     println!("{}", phrase);
// }

// fn main() {
//     print_line("Hello, world!");
// }

fn main() {

    let a = 48;
    let b = 18;
    println!("The greatest common divisor of {} and {} is {}", a, b, gcd(a, b));
}

fn gcd(mut a: u32, mut b: u32) -> u64 {

    while a != 0 {
        if a < b {
            let c = a;
            a = b;
            b = c;
        }
        a = a % b;
    }
    b as u64
}