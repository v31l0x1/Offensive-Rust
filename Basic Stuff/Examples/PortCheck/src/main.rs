use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <host> <port>", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let port: u16 = args[2].parse().expect("Invalid port number");

    println!("Host: {}, Port: {}", host, port);

    let target = format!("{}:{}", host, port);
    let addr: SocketAddr = match target.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(addr) => addr,
            None => {
                eprintln!("Could not resolve address for {}", target);
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("Error resolving address for {}: {}", target, error);
            std::process::exit(1);
        }
    };

    let timeout = Duration::from_millis(1000);
    let status = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => "open",
        Err(_) => "closed",
    };

    println!("Port {} is {}", port, status);
}
