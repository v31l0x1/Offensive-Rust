use std::env;

fn main() {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let user = env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let cwd = env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    println!("Operating System: {}", os);
    println!("Architecture: {}", arch);
    println!("User: {}", user);
    println!("Current Working Directory: {}", cwd);
}
