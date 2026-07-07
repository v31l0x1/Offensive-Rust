use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

fn scan_port(host: &str, port: u16, timeout: Duration) {
    let addr = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = addr
        .to_socket_addrs()
        .expect("Invalid address")
        .next()
        .expect("Could not resolve address");

    let status = match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(_) => "OPEN",
        Err(_) => "CLOSED",
    };

    let service = match port {
        21 => "FTP",
        22 => "SSH",
        25 => "SMTP",
        80 => "HTTP",
        443 => "HTTPS",
        445 => "SMB",
        3389 => "RDP",
        5986 => "WinRM",
        _ => "unknown",
    };

    if status != "CLOSED" {
        println!("Port {} ({}) is {}", port, service, status);
    }

    // println!("Port {} ({}) is {}", port, service, status);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: {} <host> <start>-<end> <timeout>", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let port_range = args[2].split('-').collect::<Vec<&str>>();
    let start_port: u16 = port_range[0].parse().expect("Invalid start port number");
    let end_port: u16 = port_range[1].parse().expect("Invalid end port number");
    let timeout: Duration = Duration::from_millis(args[3].parse().expect("Invalid timeout value"));

    // println!("Host: {}, Port: {}, Timeout: {:?}", host, port, timeout);

    println!(
        "Scanning ports {} to {} on host {} with timeout {:?}",
        start_port, end_port, host, timeout
    );

    for port in start_port..=end_port {
        scan_port(host, port, timeout);
    }
}
