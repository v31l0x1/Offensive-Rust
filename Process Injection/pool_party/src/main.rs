use std::ptr::null_mut;

use windows_sys::{
    Wdk::System::SystemInformation::NtQuerySystemInformation,
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
    },
};

fn get_pid(proc_name: &str) -> u32 {
    let mut pid = 0;

    unsafe {
        let mut return_length = 0;
        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!(
                "[!] NtQuerySystemInformation failed with status: {}",
                status
            );
            return pid;
        }

        let buffer_size = return_length as usize;
        let mut buffer = vec![0u8; buffer_size];

        let status = NtQuerySystemInformation(
            5,
            buffer.as_mut_ptr() as *mut _,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!(
                "[!] NtQuerySystemInformation failed with status: {}",
                status
            );
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
                    .as_str(),
                )
            {
                pid = (*proc_info).UniqueProcessId as u32;
                break;
            }

            if (*proc_info).NextEntryOffset == 0 {
                break;
            }

            proc_info = (proc_info as *const u8).add(proc_info.read().NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn main() {
    let proc_name = "Notepad.exe";

    let pid = get_pid(proc_name);

    if pid == 0 {
        println!("[!] {} process not found", proc_name);
        return;
    }

    println!("[+] {} process found with PID: {}", proc_name, pid);
}
