// https://web.archive.org/web/20221211161146/https://modexp.wordpress.com/2019/05/24/4066/
#![allow(non_snake_case, dead_code)]

use std::{os::raw::c_void, ptr::null_mut};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        QueryFullProcessImageNameA,
    },
    UI::WindowsAndMessaging::{FindWindowExA, GetWindowThreadProcessId, HWND_MESSAGE},
};

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

fn inject_clip() {}

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
