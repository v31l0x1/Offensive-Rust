// https://web.archive.org/web/20221211161146/https://modexp.wordpress.com/2019/05/24/4066/

fn enum_clip() {}

fn inject_clip() {}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <command>", args[0]);
        println!("Commands:");
        println!("  enum_clip - Enumerate clipboards");
        println!("  inject_clip - inject to clipboard");
        return;
    }

    match args[1].as_str() {
        "enum_clip" => enum_clip(),
        "inject_clip" => inject_clip(),
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Usage: {} <command>", args[0]);
            println!("Commands:");
            println!("  enum_clip - Enumerate clipboards");
            println!("  inject_clip - inject to clipboard");
        }
    }
}
