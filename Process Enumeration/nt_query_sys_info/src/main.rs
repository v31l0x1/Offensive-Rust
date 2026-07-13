use std::ptr::null_mut;

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
    },
};

fn find_pid(proc_name: &str) -> u32 {
    let mut pid: u32 = 0;
    unsafe {
        let mut return_length: u32 = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[!] Failed to query system information: {}", status);
            return 0;
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = vec![0; buffer_size];

        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut _,
            buffer_size as u32,
            &mut return_length,
        );
        if status != 0 {
            println!("[!] Failed to query system information: {}", status);
            return 0;
        }

        let mut process_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*process_info).ImageName.Buffer.is_null()
                && proc_name.eq_ignore_ascii_case(
                    String::from_utf16_lossy(std::slice::from_raw_parts(
                        (*process_info).ImageName.Buffer,
                        (*process_info).ImageName.Length as usize / 2,
                    ))
                    .as_str(),
                )
            {
                pid = (*process_info).UniqueProcessId as u32;
                break;
            }

            if (*process_info).NextEntryOffset == 0 {
                break;
            }

            process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }
    pid
}

fn main() {
    let proc_name = String::from_utf16_lossy(
        "notepad.exe"
            .encode_utf16()
            .collect::<Vec<u16>>()
            .as_slice(),
    );

    let pid = find_pid(&proc_name);

    if pid != 0 {
        println!("Process ID of {}: {}", proc_name, pid);
    } else {
        println!("Process {} not found.", proc_name);
    }
}
