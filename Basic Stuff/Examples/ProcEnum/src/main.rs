use windows::Win32::{
    Foundation::CloseHandle,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
};

struct Process {
    pid: u32,
    ppid: u32,
    threads: u32,
    name: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <process_name>", args[0]);
        std::process::exit(1);
    }

    let process_name = args.get(1).unwrap().to_string();
    println!("[+] Searching for process: {}\n", process_name);

    let processes: Vec<Process> = match enum_proc() {
        Ok(processes) => processes,
        Err(e) => {
            eprintln!("Error enumerating processes: {}", e);
            std::process::exit(1);
        }
    };

    let matches: Vec<&Process> = processes
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case(&process_name))
        .collect();

    println!("{:^6} {:^6} {:^7} {}", "PID", "PPID", "Threads", "Name");
    println!("{}", "-".repeat(60));
    for p in matches {
        println!("{:^6} {:^6} {:^7} {}", p.pid, p.ppid, p.threads, p.name);
    }
}

fn enum_proc() -> Result<Vec<Process>, Box<dyn std::error::Error>> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(snapshot) => snapshot,
            Err(_) => return Err("Failed to create process snapshot".into()),
        };

        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut pe).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&pe.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                processes.push(Process {
                    pid: pe.th32ProcessID,
                    ppid: pe.th32ParentProcessID,
                    threads: pe.cntThreads,
                    name,
                });

                if Process32NextW(snapshot, &mut pe).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(processes)
}
