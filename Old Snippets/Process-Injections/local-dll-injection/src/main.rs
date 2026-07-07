use winapi::um::libloaderapi::LoadLibraryA;



fn pause() {
    println!("Press Enter to continue...");
    std::io::stdin().read_line(&mut String::new()).unwrap();
}

fn main() {

    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <DLL_PATH>", args[0]);
        return;
    }

    println!("Loading DLL: {}", args[1]);

    unsafe  {
        let bool = LoadLibraryA(args.get(1).unwrap().as_ptr() as *const i8);
        
        if bool.is_null() {
            println!("Failed to load DLL: {}", args[1]);
        } else {
            println!("DLL loaded successfully: {}", args[1]);
        }
    }

    pause();
}