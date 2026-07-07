use std::env;

fn main() {

    let args = env::args().collect::<Vec<String>>();
    

    if args.len() != 3 {
        println!("Usage: {} <arg1> <arg2>\n", args[0]);
        std::process::exit(0);
    }

    println!("{:?}", args);
}
