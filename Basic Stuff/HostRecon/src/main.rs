use std::env;

fn main() {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let user = env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let cwd = env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    let hostname = env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());

    let domain_name_tmp = env::var("USERDOMAIN").unwrap_or_else(|_| "Unknown".to_string());

    let domain_name: String;

    if domain_name_tmp != hostname {
        domain_name = domain_name_tmp;
    } else {
        domain_name = "WORKGROUP".to_string();
    }

    let path = env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    // Create a structured JSON object using serde_json for proper formatting
    // If you don't want to add dependencies, use the manual formatting below

    // Option 1: Manual formatting (no dependencies)
    let output = format!(
        r#"{{
            "os": "{}",
            "arch": "{}",
            "user": "{}",
            "hostname": "{}",
            "domain_name": "{}",
            "cwd": "{}",
            "path": "{}"
        }}"#,
        os, arch, user, hostname, domain_name, cwd, path
    );
    println!("{}", output);
}
