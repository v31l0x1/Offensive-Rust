fn main() {
    print_hello();
    print_values(10, 20, 30);

    let result = sum(15, 25);
    println!("The sum is: {}", result);
}

fn print_hello() {
    println!("Hello, world!");
}

fn print_values(a: i32, b: i32, c: i32){
    println!("Values are: {}, {}, {}", a, b, c);
}

fn sum(a:i32, b:i32) -> i32 {
    let sum: i32 = a + b;

    // return sum;
    sum
}