use std::mem::zeroed;

use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32, PROCESSENTRY32W, Process32First, Process32FirstW,
    Process32Next, Process32NextW, TH32CS_SNAPPROCESS,
};

fn find_pid_ansi(proc_name: &str) -> u32 {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        let mut proc_entry = zeroed::<PROCESSENTRY32>();

        proc_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut proc_entry) != 0 {
            loop {
                let file_name = proc_entry
                    .szExeFile
                    .iter()
                    .map(|&c| c as u8)
                    .take_while(|&c| c != 0)
                    .collect::<Vec<u8>>();
                if file_name.eq_ignore_ascii_case(proc_name.as_bytes()) {
                    return proc_entry.th32ProcessID;
                }

                if Process32Next(snapshot, &mut proc_entry) == 0 {
                    break;
                }
            }
        }
    }
    0
}

fn find_pid_wide(proc_name: &str) -> u32 {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        let mut proc_entry = zeroed::<PROCESSENTRY32W>();

        proc_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut proc_entry) != 0 {
            loop {
                let file_name = String::from_utf16_lossy(
                    &proc_entry
                        .szExeFile
                        .iter()
                        .take_while(|&&c| c != 0)
                        .cloned()
                        .collect::<Vec<u16>>(),
                );
                if file_name.eq_ignore_ascii_case(proc_name) {
                    return proc_entry.th32ProcessID;
                }

                if Process32NextW(snapshot, &mut proc_entry) == 0 {
                    break;
                }
            }
        }
    }
    0
}

fn main() {
    let proc_name = "notepad.exe".to_string();

    let pid = find_pid_ansi(&proc_name);
    if pid != 0 {
        println!("Process ID of {}: {}", proc_name, pid);
    } else {
        println!("Process {} not found.", proc_name);
    }

    let proc_name = String::from_utf16_lossy(
        "notepad.exe"
            .encode_utf16()
            .collect::<Vec<u16>>()
            .as_slice(),
    );
    let pid = find_pid_wide(&proc_name);
    if pid != 0 {
        println!("Process ID of {}: {}", proc_name, pid);
    } else {
        println!("Process {} not found.", proc_name);
    }
}
