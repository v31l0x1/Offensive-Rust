use std::{os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION},
    },
};

fn find_pid(process_name: &str) -> u32 {
    let mut pid = 0;
    unsafe {
        let mut return_length = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("Failed to query system information: {}", status);
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = vec![0; buffer_size];

        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("Failed to query system information: {}", status);
        }

        let mut process_information = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*process_information).ImageName.Buffer.is_null()
                && process_name.eq_ignore_ascii_case(
                    String::from_utf16_lossy(std::slice::from_raw_parts(
                        (*process_information).ImageName.Buffer,
                        (*process_information).ImageName.Length as usize / 2,
                    ))
                    .as_str(),
                )
            {
                pid = (*process_information).UniqueProcessId as u32;
                break;
            }

            if (*process_information).NextEntryOffset == 0 {
                break;
            }

            process_information = (process_information as *const u8)
                .add((*process_information).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn enum_thread(pid: u32) -> u32 {
    let mut tid: u32 = 0;

    unsafe {
        let mut return_length = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("Failed to query system information: {}", status);
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = vec![0; buffer_size];

        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("Failed to query system information: {}", status);
        }

        let mut process_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if (*process_info).UniqueProcessId as u32 == pid {
                println!("[+] Found {} threads", (*process_info).NumberOfThreads);

                let offset = (process_info as usize) - (buffer.as_ptr() as usize);

                let thread_offset = offset + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
                let thread_info_ptr =
                    buffer.as_ptr().add(thread_offset) as *const SYSTEM_THREAD_INFORMATION;

                for i in 0..(*process_info).NumberOfThreads {
                    let thread_info = thread_info_ptr.add(i as usize);
                    tid = (*thread_info).ClientId.UniqueThread as u32;
                    println!("[+] Thread ID: {}", tid);
                    // break;
                }
            }

            if (*process_info).NextEntryOffset == 0 {
                break;
            }

            process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    tid
}

fn main() {
    let process_name = "brave.exe";
    let pid = find_pid(process_name);
    if pid != 0 {
        println!("Found process '{}' with PID: {}", process_name, pid);
    } else {
        println!("Process '{}' not found.", process_name);
    }

    let thread_id = enum_thread(pid);
    if thread_id != 0 {
        println!("Found thread ID: {}", thread_id);
    } else {
        println!("No threads found for process with PID: {}", pid);
    }
}
