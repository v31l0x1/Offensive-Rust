use std::{ffi::CString, mem::{size_of, zeroed}, ptr::null_mut};

use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi::GetLastError, handleapi::CloseHandle, heapapi::{GetProcessHeap, HeapAlloc}, processthreadsapi::{
            CreateProcessA, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, OpenProcess, PROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, UpdateProcThreadAttribute
        }, winbase::{CREATE_NEW_CONSOLE, EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXA}, winnt::PROCESS_ALL_ACCESS
    },
};

const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

fn spoof_parent(process_handle: *mut c_void, process_name: &str) -> bool {
    unsafe {
        let mut startup_info_ex = zeroed::<STARTUPINFOEXA>();

        let mut process_info = zeroed::<PROCESS_INFORMATION>();

        startup_info_ex.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;


        let child = CString::new(process_name).unwrap();
        let path = CString::new("C:\\Windows\\System32\\").unwrap();

        let mut attr_size: usize = 0;

        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_size);

        startup_info_ex.lpAttributeList =
            HeapAlloc(GetProcessHeap(), 0, attr_size) as *mut PROC_THREAD_ATTRIBUTE_LIST;

        if InitializeProcThreadAttributeList(startup_info_ex.lpAttributeList, 1, 0, &mut attr_size)
            == 0
        {
            println!(
                "[-] InitializeProcThreadAttributeList failed with error: {}",
                GetLastError()
            );
            return false;
        }

        if UpdateProcThreadAttribute(
            startup_info_ex.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &process_handle as *const _ as *mut c_void,
            size_of::<*mut c_void>(),
            null_mut(),
            null_mut(),
        ) == 0
        {
            println!(
                "[-] UpdateProcThreadAttribute failed with error: {}",
                GetLastError()
            );
            return false;
        }

        if CreateProcessA(
            null_mut(),
            child.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            // EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, use if you want run cmd.exe or any other process with a new console
            EXTENDED_STARTUPINFO_PRESENT,
            null_mut(),
            path.as_ptr() as *mut i8,
            &mut startup_info_ex.StartupInfo,
            &mut process_info,
        ) == 0
        {
            println!("[-] CreateProcessA failed with error: {}", GetLastError());
            return false;
        }

        DeleteProcThreadAttributeList(startup_info_ex.lpAttributeList);
        CloseHandle(process_handle);

        println!("[+] Process created with PID: {}", process_info.dwProcessId);
    }

    return true;
}

fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {

    let args = std::env::args().collect::<Vec<String>>();

    if args.len() != 3 {
        println!("Usage: {} <pid> <process_name>", args[0]);
        return;
    }

    let pid = args[1].parse::<u32>().expect("Invalid PID");
    let process_name = &args[2];


    // let pid = 7676;
    // let process_name = "cmd.exe";

    unsafe {

        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

        if process_handle.is_null() {
            println!("[-] OpenProcess failed with error: {}", GetLastError());
            return;
        }

        if spoof_parent(process_handle, process_name) {
            println!("[+] Process created successfully with spoofed parent!");
        } else {
            println!("[-] Failed to create process with spoofed parent.");
        }

        pause();

    }


}
